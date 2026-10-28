"""Swift code-graph export lane: pack, catalog section, column contract and the swift-synthetic recording.

CodeQL extracts Swift only on macOS, so the swift-synthetic recording is hand-authored (see its
provenance.json) and the live tier (tests/live/test_codeql_graph_export_swift_live.py) skips until a
macOS executor exists. These offline tests keep the pack, catalog and recording consistent so the lane
is ready the moment one does. Regenerate the normalized golden with
``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`` after an intended rule change and review the diff.
"""
from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import normalize_scope
from tests.fixtures.graph.expectations import load_expectations, unmet

ROOT = Path(__file__).resolve().parents[2]
EXPORT_ROOT = ROOT / "rules" / "codeql-graph-export"
PACK = EXPORT_ROOT / "swift"
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "swift-synthetic"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "swift-synthetic" / "normalized.json"
COLUMNS = json.loads((EXPORT_ROOT / "columns.json").read_text(encoding="utf-8"))
CATALOG = json.loads((EXPORT_ROOT / "catalog.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((EXPORT_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
LIBRARY = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
TARGET_PATH = "src/Synthetic.swift"
SOURCE = SourceFile.from_bytes((FIXTURE / "source" / "Synthetic.swift").read_bytes())
SCOPE = {"scope_id": "codeql-unit-swift-synthetic", "language": "swift", "build_unit_id": "swift-synthetic",
         "component_id": "component:swift-synthetic", "root": "src",
         "files": [{"path": TARGET_PATH, "sha256": SOURCE.sha256}]}


def _recording() -> dict:
    loaded = load_graph_exports(FIXTURE / "exports", bytes_limit=c.GraphSettings().max_export_bytes)
    return json.loads(json.dumps(loaded))


def _rules(kind: str) -> list[dict]:
    return CATALOG["languages"]["swift"][kind]


@pytest.fixture(scope="module")
def normalized():
    return normalize_scope(_recording(), scope=SCOPE, target_snapshot="target-sha256:" + "3" * 64,
                           sources={TARGET_PATH: SOURCE}, catalog=load_catalog(), settings=c.GraphSettings(),
                           tool_version="2.27.0", export_pack_sha256="e" * 64)


def _family(result, family: c.Family) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family is family]


# --------------------------------------------------------------------------- recording


def test_recording_meets_every_expectation() -> None:
    assert unmet(_recording(), load_expectations(FIXTURE)) == []


def test_every_provenance_case_has_an_expectation() -> None:
    provenance = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["fixture"] == "swift-synthetic" and provenance["live_refreshable"] is False
    assert {item["case"] for item in load_expectations(FIXTURE)["expectations"]} == set(provenance["cases"])


def test_recording_manifest_identifies_the_swift_pack() -> None:
    manifest = json.loads((FIXTURE / "exports" / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["language"] == "swift"
    assert manifest["pack"]["query_id"] == "graph-export-swift"
    assert manifest["pack"]["query_pack"] == "appsec-review/graph-export-swift"
    assert manifest["pack"]["file_count"] == len([path for path in PACK.iterdir() if path.is_file()])


# --------------------------------------------------------------------------- normalization


def test_recording_normalizes_into_every_family_with_catalog_classes(normalized) -> None:
    produced = normalized.to_json()
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(produced)
    assert GOLDEN.read_bytes() == produced
    counts = {family.value: len(_family(normalized, family)) for family in c.Family}
    assert all(counts.values()), counts
    for fact in normalized.facts:
        entity = fact.to_entity()
        assert entity.payload["admissibility"] == c.admissibility(fact.payload)

    sinks = {fact.location.start_line: fact.payload["result"] for fact in _family(normalized, c.Family.SINK_SITE)}
    assert {line: sink["sink_class"] for line, sink in sinks.items()} == {
        10: "path_access", 32: "sql_query", 42: "command_execution", 47: "server_side_request",
        52: "deserialization", 57: "path_access", 63: "allocation_size", 66: "allocation_size",
        76: "unclassified"}
    sources = {fact.location.start_line: fact.payload["result"]["source_class"]
               for fact in _family(normalized, c.Family.ENTRY_POINT)}
    assert sources == {22: "remote", 36: "argv", 41: "environment", 51: "remote"}


def test_paths_guards_ranges_and_summaries_attach_to_their_sinks(normalized) -> None:
    paths = _family(normalized, c.Family.DATAFLOW_PATH)
    assert len(paths) == 9
    by_sink_line = {}
    for fact in paths:
        steps = fact.payload["result"]["steps"]
        by_sink_line.setdefault(steps[-1]["location"]["start_line"], []).append(fact)
    assert set(by_sink_line) == {10, 32, 42, 47, 52, 57, 63, 66, 76}
    [sql] = by_sink_line[32]
    assert [step["role"] for step in sql.payload["result"]["steps"]] == [
        "source", "step", "return", "call", "step", "step", "return", "sink"]
    [safe] = by_sink_line[57]
    assert [item["api"] for item in safe.payload["result"]["sanitizers"]] == ["resolvingSymlinksInPath"]

    guards = {fact.payload["result"]["guard_state"] for fact in _family(normalized, c.Family.GUARD_FACT)}
    assert guards == {"dominating", "non_dominating", "none"}
    ranges = {fact.payload["result"]["applicability"] for fact in _family(normalized, c.Family.RANGE_FACT)}
    assert ranges == {"integral", "not_applicable"}

    summaries = {fact.payload["result"]["function"]["display"]: fact.payload["result"]
                 for fact in _family(normalized, c.Family.FLOW_SUMMARY)}
    assert set(summaries) == {"buildQuery", "FileStore.save"}
    assert [pair["to"]["kind"] for pair in summaries["buildQuery"]["pairs"]] == ["return"]
    assert [pair["to"]["kind"] for pair in summaries["FileStore.save"]["pairs"]] == ["sink"]
    calls = _family(normalized, c.Family.CALL_SITE)
    dispatch = {fact.payload["result"]["callee"]["dispatch"] for fact in calls}
    assert {"direct", "external_undefined", "virtual_resolved", "unresolved_indirect"} <= dispatch


# --------------------------------------------------------------------------- pack and contracts


def _query_predicates() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    found = {}
    for path in sorted(PACK.glob("*.ql")):
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", path.read_text(encoding="utf-8")):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    return found


def test_columns_section_mirrors_cpp_and_equals_the_ql_query_predicates() -> None:
    swift, cpp = COLUMNS["languages"]["swift"], COLUMNS["languages"]["cpp"]
    assert (swift["pack_root"], swift["query_pack"]) == ("swift", "appsec-review/graph-export-swift")
    shape = lambda section: [(q["query_id"], q["query_file"], q["result_set"], q.get("family"),
                              [(col["name"], col["type"]) for col in q["columns"]]) for q in section["queries"]]
    assert shape(swift) == shape(cpp)
    predicates = _query_predicates()
    assert sorted(predicates) == sorted(query["query_id"] for query in swift["queries"])
    for query in swift["queries"]:
        assert all(column["meaning"] for column in query["columns"])
        assert predicates[query["query_id"]] == (
            query["query_file"], [(column["type"], column["name"]) for column in query["columns"]])
    suite = (PACK / "graph-export.qls").read_text(encoding="utf-8")
    assert sorted(re.findall(r"- query: (\S+)", suite)) == sorted({q["query_file"] for q in swift["queries"]})
    for path in PACK.glob("*.ql"):
        text = path.read_text(encoding="utf-8")
        assert "LIVE-UNVERIFIED" in text and "@kind table" in text and "select " not in text
    qlpack = (PACK / "qlpack.yml").read_text(encoding="utf-8")
    assert "name: appsec-review/graph-export-swift" in qlpack and "version: 1.0.0" in qlpack
    assert "codeql/swift-all" in qlpack


def test_pack_declares_the_scope_externals_and_restricts_every_query_by_exported() -> None:
    assert "external predicate exportScope(string mode, int depth);" in LIBRARY
    assert "external predicate exportSeed(string path, int startLine, int endLine);" in LIBRARY
    for name in ("seedFunction", "near", "exported", "wholeProgram"):
        assert re.search(rf"\bpredicate {name}\(", LIBRARY), name
    assert "exportedExpr(sinkExpr)" in LIBRARY and "exportedNode(n)" in LIBRARY
    for name in ("CallSites.ql", "FlowSummaries.ql"):
        assert "GraphExport::exported(" in (PACK / name).read_text(encoding="utf-8"), name
    assert "GraphExport::exportedNode(n)" in (PACK / "Paths.ql").read_text(encoding="utf-8")
    for name in ("Seeds.ql", "Neighborhood.ql"):
        assert "not GraphExport::wholeProgram()" in (PACK / name).read_text(encoding="utf-8")


def _ql_pairs(predicate: str) -> set[tuple[str, int]]:
    body = LIBRARY.split(f"predicate {predicate}(", 1)[1].split("\n  }\n", 1)[0]
    return {(name, int(index)) for name, index in re.findall(r'name = "(\w+)" and arg = (-?\d+)', body)}


def test_catalog_api_and_model_rules_equal_what_the_queries_can_emit() -> None:
    sink_api = {(rule["match"]["api"], rule["match"]["argument_index"]) for rule in _rules("sinks")
                if "api" in rule["match"]}
    source_api = {(rule["match"]["api"], rule["match"]["index"]) for rule in _rules("sources")
                  if "api" in rule["match"]}
    assert sink_api == _ql_pairs("apiSinkArgument")
    assert source_api == _ql_pairs("apiSourceArgument")
    sanitizers = set(re.findall(r'"(\w+)"', LIBRARY.split("predicate sanitizerApi(", 1)[1].split("}", 1)[0]))
    assert sanitizers == {rule["api"] for rule in _rules("sanitizers")}
    emitted_sink_models = set(re.findall(r'result = "(\w+Sink)"', LIBRARY.split("string sinkModel(", 1)[1]
                                         .split("\n  }\n", 1)[0]))
    schema_models = SCHEMA["$defs"]["models_swift"]["properties"]["sinks"]["items"]["properties"]["match"][
        "properties"]["model"]["enum"]
    assert set(schema_models) == emitted_sink_models
    classified = {rule["match"]["model"] for rule in _rules("sinks") if "model" in rule["match"]}
    # PredicateInjectionSink is emitted but deliberately unclassified: no SinkClass fits it.
    assert emitted_sink_models - classified == {"PredicateInjectionSink"}
    emitted_source_models = set(re.findall(r'result = "(\w+)"', LIBRARY.split("string modelClass(", 1)[1]
                                           .split("\n  }\n", 1)[0]))
    assert {rule["match"]["model"] for rule in _rules("sources") if "model" in rule["match"]} <= emitted_source_models
    assert CATALOG["languages"]["swift"]["export_pack"] == COLUMNS["languages"]["swift"]["query_pack"]
    assert CATALOG["languages"]["swift"]["model_library"] == "codeql/swift-all"


def test_catalog_swift_section_validates_and_uses_closed_vocabularies() -> None:
    Draft202012Validator(SCHEMA).validate(CATALOG)
    sink_classes = {value.value for value in c.SinkClass} - {"unclassified"}
    source_classes = {value.value for value in c.SourceClass} - {"unclassified"}
    assert {rule["sink_class"] for rule in _rules("sinks")} <= sink_classes
    assert {rule["source_class"] for rule in _rules("sources")} <= source_classes
    rule_ids = [rule["rule_id"] for kind in ("sinks", "sources", "sanitizers") for rule in _rules(kind)]
    assert len(rule_ids) == len(set(rule_ids)) and all(rule_id.startswith("swift.") for rule_id in rule_ids)
    assert load_catalog().language("swift").sanitizer_apis == {"resolvingSymlinksInPath", "lexicallyNormalized",
                                                               "sqlite3_bind_text"}


@pytest.mark.parametrize("mutate", [
    lambda doc: doc["languages"]["swift"]["sinks"][-1]["match"].update(model="SomethingElse"),
    lambda doc: doc["languages"]["swift"]["sources"][-1]["match"].update(model="SomethingElse"),
    lambda doc: doc["languages"]["swift"]["sinks"][0]["match"].pop("declared_in"),
    lambda doc: doc["languages"]["swift"]["sinks"][0].update(sink_class="unclassified"),
])
def test_schema_rejects_an_unknown_swift_model_or_an_open_rule(mutate) -> None:
    document = copy.deepcopy(CATALOG)
    mutate(document)
    with pytest.raises(ValidationError):
        Draft202012Validator(SCHEMA).validate(document)
