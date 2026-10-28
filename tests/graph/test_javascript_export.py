"""The JavaScript/TypeScript graph-export pack, its catalog section and its hand-authored recording.

The recording over ``tests/fixtures/graph/codeql_export/javascript-synthetic/source`` is normalized
against its sources staged at ``src/<file>`` with CodeQL scope root ``src``. The golden output lives in
``tests/fixtures/graph/expected/javascript-synthetic/normalized.json``; regenerate it with
``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1``.
"""
from __future__ import annotations

import copy
import json
import os
import re
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
RULES = ROOT / "rules" / "codeql-graph-export"
PACK = RULES / "javascript"
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "javascript-synthetic"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "javascript-synthetic" / "normalized.json"
COLUMNS = json.loads((RULES / "columns.json").read_text(encoding="utf-8"))
CATALOG = json.loads((RULES / "catalog.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((RULES / "catalog.schema.json").read_text(encoding="utf-8"))
LIBRARY = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
SNAPSHOT = "target-sha256:" + "4" * 64
SOURCES = {f"src/{path.name}": SourceFile.from_bytes(path.read_bytes())
           for path in sorted((FIXTURE / "source").iterdir())}
SCOPE = {"scope_id": "codeql-unit-javascript-synthetic", "language": "javascript",
         "build_unit_id": "javascript-synthetic", "component_id": "component:javascript-synthetic", "root": "src",
         "files": [{"path": path, "sha256": source.sha256} for path, source in SOURCES.items()]}


def _recording() -> dict[str, dict[str, Any]]:
    loaded = load_graph_exports(FIXTURE / "exports", bytes_limit=c.GraphSettings().max_export_bytes)
    return json.loads(json.dumps(loaded))


def _rules(kind: str) -> list[dict]:
    return CATALOG["languages"]["javascript"][kind]


@pytest.fixture(scope="module")
def normalized():
    return normalize_scope(_recording(), scope=SCOPE, target_snapshot=SNAPSHOT, sources=SOURCES,
                           catalog=load_catalog(), settings=c.GraphSettings(), tool_version="2.27.0",
                           export_pack_sha256="e" * 64)


def _family(result, family: str) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family.value == family]


# --------------------------------------------------------------------------- recording


def test_recording_meets_every_expectation() -> None:
    assert unmet(_recording(), load_expectations(FIXTURE)) == []


def test_every_provenance_case_has_an_expectation() -> None:
    provenance = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["fixture"] == "javascript-synthetic" and provenance["recording"] == "hand-authored"
    assert {item["case"] for item in load_expectations(FIXTURE)["expectations"]} == set(provenance["cases"])


def test_recording_is_a_whole_program_javascript_export_with_every_query() -> None:
    manifest = json.loads((FIXTURE / "exports" / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["language"] == "javascript" and manifest["scope"]["mode"] == "whole_program"
    assert manifest["pack"]["query_pack"] == "appsec-review/graph-export-javascript"
    assert set(_recording()) == set(export_columns("javascript"))


# --------------------------------------------------------------------------- normalization


def test_normalize_publishes_every_family_exactly_with_catalog_classes(normalized) -> None:
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(normalized.to_json())
    assert GOLDEN.read_bytes() == normalized.to_json()
    counts = {family.value: len(_family(normalized, family.value)) for family in c.Family}
    assert counts == {"call_site": 30, "sink_site": 11, "entry_point": 9, "flow_summary": 4, "dataflow_path": 11,
                      "guard_fact": 12, "range_fact": 11}
    sink_classes = sorted(fact.payload["result"]["sink_class"] for fact in _family(normalized, "sink_site"))
    assert sink_classes == sorted(["sql_query", "command_execution", "command_execution", "path_access",
                                   "server_side_request", "deserialization", "html_output", "command_execution",
                                   "log_output", "crypto_misuse", "path_access"])
    source_classes = sorted(fact.payload["result"]["source_class"] for fact in _family(normalized, "entry_point"))
    assert source_classes == sorted(["remote"] * 6 + ["argv", "environment", "local_user"])
    for fact in normalized.facts:
        fact.to_entity()
        if fact.family is not c.Family.CALL_SITE:
            assert fact.payload["exact"], fact.name
    assert not [symbol.name for symbol in normalized.symbols if symbol.payload["gaps"]]


def test_ranges_are_a_named_not_applicable_gap_never_clean(normalized) -> None:
    ranges = _family(normalized, "range_fact")
    assert ranges and all(any(gap.startswith("not_applicable:") for gap in fact.payload["gaps"]) for fact in ranges)


def test_coverage_names_the_unresolved_calls_and_nothing_else_is_partial(normalized) -> None:
    coverage = {row.family.value: row for row in normalized.coverage}
    assert coverage["call_site"].status is c.Coverage.PARTIAL
    assert coverage["call_site"].counts == {"unresolved_indirect": 10}
    assert all(row.status is c.Coverage.COMPLETE for name, row in coverage.items() if name != "call_site")


def test_paths_carry_sources_sanitizers_and_cross_function_steps(normalized) -> None:
    paths = _family(normalized, "dataflow_path")
    by_sink: dict[str, list[dict]] = {}
    for fact in paths:
        by_sink.setdefault(fact.name.split(" -> ", 1)[1], []).append(fact.payload["result"])
    assert all(result["source"]["entry_point"] for results in by_sink.values() for result in results)
    [sanitized] = by_sink["readFileSync [path_access]"]
    assert [item["api"] for item in sanitized["sanitizers"]] == ["basename"]
    assert len(by_sink["execSync [command_execution]"]) == 3
    [sql] = by_sink["query [sql_query]"]
    assert [step["role"] for step in sql["steps"]] == ["source", "call", "step", "step", "sink"]


def test_guards_distinguish_the_guarded_and_unguarded_exec(normalized) -> None:
    states = sorted((fact.payload["result"]["guard_state"], fact.payload["result"]["constrains_sink_operand"])
                    for fact in _family(normalized, "guard_fact") if fact.name.endswith("-> exec [command_execution]"))
    assert states == [("dominating", True), ("non_dominating", "unknown"), ("none", False)]


# --------------------------------------------------------------------------- pack <-> contract


def _query_predicates() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    found = {}
    for path in sorted(PACK.glob("*.ql")):
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", path.read_text(encoding="utf-8")):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    return found


def test_columns_section_equals_the_ql_query_predicates_and_the_cpp_shape() -> None:
    section = COLUMNS["languages"]["javascript"]
    assert section["query_pack"] == "appsec-review/graph-export-javascript"
    queries = section["queries"]
    cpp = {query["query_id"]: query for query in COLUMNS["languages"]["cpp"]["queries"]}
    predicates = _query_predicates()
    assert sorted(predicates) == sorted(cpp) == sorted(query["query_id"] for query in queries)
    for query in queries:
        assert predicates[query["query_id"]] == (
            query["query_file"], [(column["type"], column["name"]) for column in query["columns"]])
        reference = cpp[query["query_id"]]
        assert [(col["name"], col["type"]) for col in query["columns"]] == [
            (col["name"], col["type"]) for col in reference["columns"]]
        assert query.get("family") == reference.get("family") and query["query_file"] == reference["query_file"]
    in_families = {query_id for ids in FAMILY_QUERIES.values() for query_id in ids}
    assert in_families | {"seed_functions", "neighborhood"} == set(export_columns("javascript"))
    suite = (PACK / "graph-export.qls").read_text(encoding="utf-8")
    assert sorted(re.findall(r"- query: (\S+)", suite)) == sorted({query["query_file"] for query in queries})
    for path in PACK.glob("*.ql"):
        text = path.read_text(encoding="utf-8")
        assert "LIVE-UNVERIFIED" in text and "@kind table" in text and "select " not in text


def test_pack_metadata_and_scope_externals() -> None:
    qlpack = (PACK / "qlpack.yml").read_text(encoding="utf-8")
    assert "name: appsec-review/graph-export-javascript" in qlpack and "version: 1.0.0" in qlpack
    assert "codeql/javascript-all:" in qlpack
    assert "external predicate exportScope(string mode, int depth);" in LIBRARY
    assert "external predicate exportSeed(string path, int startLine, int endLine);" in LIBRARY
    for name in ("seedFunction", "near", "exported", "wholeProgram"):
        assert re.search(rf"\bpredicate {name}\(", LIBRARY), name
    assert "exportedNode(sinkNode)" in LIBRARY and "exportedNode(n)" in LIBRARY
    for name in ("CallSites.ql", "FlowSummaries.ql"):
        assert "GraphExport::exported(" in (PACK / name).read_text(encoding="utf-8"), name
    assert "GraphExport::exportedNode(n)" in (PACK / "Paths.ql").read_text(encoding="utf-8")
    for name in ("Seeds.ql", "Neighborhood.ql"):
        assert "not GraphExport::wholeProgram()" in (PACK / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- catalog


def _ql_pairs(predicate: str) -> set[tuple[str, int]]:
    body = LIBRARY.split(f"predicate {predicate}(", 1)[1].split("\n  }\n", 1)[0]
    return {(name, int(index)) for name, index in re.findall(r'name = "(\w+)" and arg = (-?\d+)', body)}


def _ql_modules() -> dict[str, set[str]]:
    body = LIBRARY.split("predicate apiModule(", 1)[1].split("\n  }\n", 1)[0]
    modules: dict[str, set[str]] = {}
    for names, module in re.findall(r'name = (\[[^\]]*\]|"\w+") and m = "([\w-]+)"', body):
        for name in re.findall(r'"(\w+)"', names):
            modules.setdefault(name, set()).add(module)
    return modules


def test_catalog_api_and_model_rules_equal_what_the_queries_can_emit() -> None:
    sink_api = {(rule["match"]["api"], rule["match"]["argument_index"]) for rule in _rules("sinks")
                if "api" in rule["match"]}
    source_api = {(rule["match"]["api"], rule["match"]["index"]) for rule in _rules("sources")
                  if "api" in rule["match"]}
    assert sink_api == _ql_pairs("apiSinkArgument")
    assert source_api == _ql_pairs("apiSourceArgument")
    modules = _ql_modules()
    for rule in _rules("sinks") + _rules("sources"):
        if "api" in rule["match"]:
            assert set(rule["match"]["declared_in"]) == modules[rule["match"]["api"]], rule["rule_id"]
    sanitizers = set(re.findall(r'"(\w+)"', LIBRARY.split("predicate sanitizerApi(", 1)[1].split("}", 1)[0]))
    assert sanitizers == {rule["api"] for rule in _rules("sanitizers")}
    sink_models = set(re.findall(r'model = "(\w+::Sink)"', LIBRARY))
    assert sink_models == {rule["match"]["model"] for rule in _rules("sinks") if "model" in rule["match"]}
    threat_models = re.findall(r'"(\w+)"', LIBRARY.split("predicate namedThreatModel(", 1)[1].split("}", 1)[0])
    source_models = {"RemoteFlowSource", "ThreatModelSource"} | {f"ThreatModelSource.{tm}" for tm in threat_models}
    assert source_models == {rule["match"]["model"] for rule in _rules("sources") if "model" in rule["match"]}
    definition = SCHEMA["$defs"]["models_javascript"]
    assert sink_models <= set(json.dumps(definition).split('"')) and source_models <= set(
        json.dumps(definition).split('"'))


def test_catalog_section_validates_and_classifies_the_recording() -> None:
    Draft202012Validator(SCHEMA).validate(CATALOG)
    catalog = load_catalog()
    assert catalog.language("javascript").language == catalog.language("typescript").language == "javascript"
    recording = _recording()
    for query_id, classify, unclassified in (("sink_sites", "classify_sink", "unclassified"),
                                            ("source_sites", "classify_source", "unclassified")):
        columns = recording[query_id]["columns"]
        for row in recording[query_id]["rows"]:
            result = getattr(catalog.language("javascript"), classify)(dict(zip(columns, row)))
            assert str(getattr(result, "value", result)) != unclassified, row


@pytest.mark.parametrize("mutate", [
    lambda doc: next(rule for rule in doc["languages"]["javascript"]["sinks"] if "model" in rule["match"])[
        "match"].update(model="SomethingElse::Sink"),
    lambda doc: next(rule for rule in doc["languages"]["javascript"]["sources"] if "model" in rule["match"])[
        "match"].update(model="ThreatModelSource.unknown"),
    lambda doc: doc["languages"]["javascript"]["sinks"][0].update(sink_class="unclassified"),
])
def test_schema_rejects_an_unknown_javascript_model_or_class(mutate) -> None:
    document = copy.deepcopy(CATALOG)
    mutate(document)
    with pytest.raises(ValidationError):
        Draft202012Validator(SCHEMA).validate(document)
