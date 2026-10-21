"""Graph normalizer (code-graph chunk C3): docs/architecture/code-graph-precomputation.md section 10.

The synthetic C1 recording is normalized against its source staged at the target path
``src/synthetic.cpp`` with CodeQL scope root ``src`` (the ``sarif.py::map_location`` prefix rule).
The golden output lives in ``tests/fixtures/graph/expected/synthetic/normalized.json``; regenerate it
with ``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`` after an intended rule change and review the diff.
"""
from __future__ import annotations

import copy
import json
import os
import random
import re
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import (
    CATALOG_PATH,
    CatalogError,
    load_catalog,
    parse_catalog,
)
from appsec_review.graph.correlate import CorrelationState, correlate
from appsec_review.graph.crosscheck import (
    CrossCheckInputs,
    SecondaryShard,
    SourceFile,
    cross_check,
)
from appsec_review.graph.normalize import normalize_scope
from appsec_review.retrieval import (
    EntityKind,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RelationKind,
    RetrievalCore,
    index_fingerprint,
    write_manifest,
)
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json, file_sha256

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "synthetic"
NATIVE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "native"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "synthetic" / "normalized.json"
SNAPSHOT = "target-sha256:" + "3" * 64
TARGET_PATH = "src/synthetic.cpp"
SOURCE_BYTES = (FIXTURE / "source" / "synthetic.cpp").read_bytes()
SOURCE = SourceFile.from_bytes(SOURCE_BYTES)
SOURCES = {TARGET_PATH: SOURCE}
SCOPE = {"scope_id": "codeql-unit-synthetic", "language": "cpp", "build_unit_id": "synthetic",
         "component_id": "component:synthetic", "root": "src",
         "files": [{"path": TARGET_PATH, "sha256": SOURCE.sha256}]}
CATALOG = load_catalog()
RUN_ID = "2026-10-12-0003"


def _exports(name: Path = FIXTURE) -> dict[str, dict[str, Any]]:
    loaded = load_graph_exports(name / "exports", bytes_limit=c.GraphSettings().max_export_bytes)
    return json.loads(json.dumps(loaded))


def _normalize(exports: Mapping[str, Any] | None = None, *, settings: c.GraphSettings | None = None,
               scope: Mapping[str, Any] = SCOPE, sources: Mapping[str, SourceFile] = SOURCES):
    return normalize_scope(_exports() if exports is None else exports, scope=scope, target_snapshot=SNAPSHOT,
                           sources=sources, catalog=CATALOG, settings=settings or c.GraphSettings(),
                           tool_version="2.27.0", export_pack_sha256="e" * 64)


def _rows(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(zip(document["columns"], row)) for row in document["rows"]]


def _set_rows(document: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    document["rows"] = [[row[name] for name in document["columns"]] for row in rows]
    document["row_count"] = len(rows)


def _family(result, family: str) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family.value == family]


def _at(fact: c.GraphFact) -> tuple[int, int]:
    return fact.location.start_line, fact.location.start_column


def _symbol(result, name: str) -> str:
    [record] = [item for item in result.symbols if item.name == name]
    return record.identity.value


@pytest.fixture(scope="module")
def synthetic():
    return _normalize()


# --------------------------------------------------------------------------- golden and determinism


def test_synthetic_fixture_matches_the_golden_output(synthetic) -> None:
    produced = synthetic.to_json()
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(produced)
    assert GOLDEN.read_bytes() == produced
    counts = {family.value: len(_family(synthetic, family.value)) for family in c.Family}
    assert counts == {"call_site": 17, "sink_site": 7, "entry_point": 2, "flow_summary": 4, "dataflow_path": 5,
                      "guard_fact": 10, "range_fact": 7}
    for fact in synthetic.facts:
        entity = fact.to_entity()  # every fact satisfies the shared contract
        assert entity.payload["admissibility"] == c.admissibility(fact.payload)
        assert fact.payload["cross_check"] == {"rule": c.CROSS_CHECK_RULE, "state": "not_covered", "producers": []}


@pytest.mark.parametrize("seed", [1, 7, 2026])
def test_output_is_byte_identical_across_runs_and_shuffled_rows(synthetic, seed: int) -> None:
    exports = _exports()
    rng = random.Random(seed)
    for document in exports.values():
        rng.shuffle(document["rows"])
    shuffled = dict(rng.sample(sorted(exports.items()), len(exports)))
    assert _normalize(shuffled).to_json() == synthetic.to_json() == _normalize().to_json()


# --------------------------------------------------------------------------- locations and symbols


def test_locations_derive_bytes_with_exclusive_ends_and_symbols_sit_on_the_defining_name(synthetic) -> None:
    [sink] = [fact for fact in _family(synthetic, "sink_site") if _at(fact) == (45, 3)]
    location = sink.location
    assert SOURCE_BYTES[location.start_byte:location.end_byte] == b"memcpy(dst, src, len)"
    assert (location.path, location.end_column, location.mapping_method) == (TARGET_PATH, 24, "codeql-location-exact")
    assert location.file_sha256 == SOURCE.sha256 and not location.ambiguous
    by_name = {item.name: item for item in synthetic.symbols}
    for name, text in (("copy_unchecked", b"copy_unchecked"), ("CopyHandler::handle", b"handle"), ("main", b"main")):
        symbol = by_name[name]
        assert SOURCE_BYTES[symbol.location.start_byte:symbol.location.end_byte] == text
        assert symbol.payload["producer"] == "codeql-export" and symbol.payload["exact"] is True
        assert symbol.payload["scope"]["scope_id"] == SCOPE["scope_id"]
    assert sink.payload["result"]["enclosing_function"]["symbol"] == by_name["copy_unchecked"].identity.value
    calls = [fact for fact in _family(synthetic, "call_site") if fact.payload["result"]["callee"]["display"]
             == "copy_unchecked"]
    assert {fact.payload["result"]["callee"]["symbol"] for fact in calls} == {by_name["copy_unchecked"].identity.value}
    assert {fact.payload["result"]["caller"]["symbol"] for fact in calls} == {by_name["main"].identity.value}


def test_relations_link_symbols_calls_sinks_guards_ranges_summaries_and_flows(synthetic) -> None:
    kinds = {(relation.kind, LogicalIdentity.parse(relation.source_id).kind.value,
              LogicalIdentity.parse(relation.target_id).kind.value) for relation in synthetic.relations}
    assert kinds == {
        (RelationKind.CONTAINS, "symbol", "call_site"), (RelationKind.CONTAINS, "symbol", "sink_site"),
        (RelationKind.CONTAINS, "symbol", "entry_point"), (RelationKind.CALLS, "call_site", "symbol"),
        (RelationKind.GUARDS, "guard_fact", "sink_site"), (RelationKind.DERIVED_FROM, "range_fact", "sink_site"),
        (RelationKind.DERIVED_FROM, "flow_summary", "symbol"), (RelationKind.FLOWS_TO, "entry_point", "sink_site"),
    }
    paths = {fact.identity.value: fact for fact in _family(synthetic, "dataflow_path")}
    for relation in synthetic.relations:
        if relation.kind is RelationKind.FLOWS_TO:
            assert relation.payload["path_id"] in paths
            assert relation.payload["path_id"] == relation.payload["path_ids"][0]
    assert len({relation.relation_id for relation in synthetic.relations}) == len(synthetic.relations)


def test_a_line_only_step_makes_the_path_inexact_and_ineligible() -> None:
    exports = _exports()
    rows = _rows(exports["path_edges"])
    for row in rows:  # the getenv flow's middle node `atoi(getenv(...))` loses its columns
        for side in ("from", "to"):
            if (row[f"{side}_start_line"], row[f"{side}_start_column"]) == (55, 11):
                row[f"{side}_start_column"] = row[f"{side}_end_column"] = 0
    _set_rows(exports["path_edges"], rows)
    result = _normalize(exports)
    [path] = [fact for fact in _family(result, "dataflow_path")
              if fact.payload["result"]["source"]["source_class"] == "environment"]
    assert path.payload["exact"] is False and path.payload["admissibility"]["direct_eligible"] is False
    assert "inexact_location" in path.payload["admissibility"]["ineligibility_reasons"]
    assert any(gap.startswith("ambiguous_step_location: step 1 ") for gap in path.payload["gaps"])
    step = path.payload["result"]["steps"][1]["location"]
    assert step["ambiguous"] is True and step["mapping_method"] == "codeql-line-only" and step["start_line"] == 55
    assert result.coverage_for("dataflow_path").status is c.Coverage.PARTIAL


def test_macro_condition_maps_to_the_expansion_site_and_is_not_exact(synthetic) -> None:
    macro = [fact for fact in _family(synthetic, "guard_fact")
             if fact.payload["result"]["condition"] and fact.payload["result"]["condition"]["in_macro"]]
    assert len(macro) == 2
    for fact in macro:
        assert fact.payload["exact"] is False and fact.location.ambiguous
        assert fact.location.mapping_method == "codeql-macro-expansion-site" and _at(fact) == (36, 7)
        assert any(gap.startswith("macro_expansion_site") for gap in fact.payload["gaps"])


def test_a_source_hash_mismatch_rejects_the_scope() -> None:
    scope = {**SCOPE, "files": [{"path": TARGET_PATH, "sha256": "0" * 64}]}
    with pytest.raises(IntegrityError, match="hash differs"):
        _normalize(scope=scope)


def test_export_columns_differing_from_the_contract_reject_the_scope() -> None:
    exports = _exports()
    exports["ranges"]["columns"] = [*exports["ranges"]["columns"][:-1], "upper_bound"]
    with pytest.raises(IntegrityError, match="columns"):
        _normalize(exports)


def test_rows_outside_the_accepted_sources_are_counted_not_published() -> None:
    exports = _exports()
    rows = _rows(exports["call_sites"])
    rows[0]["call_path"] = "elsewhere.cpp"
    _set_rows(exports["call_sites"], rows)
    result = _normalize(exports)
    row = result.coverage_for("call_site")
    assert len(_family(result, "call_site")) == 16 and row.counts["unmapped_rows"] == 1
    assert row.status is c.Coverage.PARTIAL and any(gap.startswith("unmapped_location") for gap in row.gaps)


# --------------------------------------------------------------------------- families


def test_unresolved_indirect_call_is_published_counted_and_makes_coverage_partial(synthetic) -> None:
    [fact] = [fact for fact in _family(synthetic, "call_site")
              if fact.payload["result"]["callee"]["dispatch"] == "unresolved_indirect"]
    result = fact.payload["result"]
    assert result["callee"]["symbol"] is None and result["callee"]["candidate_count"] == 0
    assert result["caller"]["symbol"] == _symbol(synthetic, "run_callback") and result["in_loop"] is False
    assert any(gap.startswith("unresolved_indirect") for gap in fact.payload["gaps"])
    row = synthetic.coverage_for("call_site")
    assert row.status is c.Coverage.PARTIAL and row.counts["unresolved_indirect"] == 1
    virtual = [fact for fact in _family(synthetic, "call_site")
               if fact.payload["result"]["callee"]["dispatch"] == "virtual_resolved"]
    assert len(virtual) == 2 and len({_at(fact) for fact in virtual}) == 1
    assert {fact.payload["result"]["callee"]["candidate_count"] for fact in virtual} == {2}
    assert not [r for r in synthetic.relations if r.kind is RelationKind.CALLS and r.source_id == fact.identity.value]


def test_in_loop_string_booleans_become_booleans() -> None:
    exports = _exports()
    rows = _rows(exports["call_sites"])
    for row in rows:
        if row["callee_name"] == "strlen":
            row["in_loop"] = "true"
    _set_rows(exports["call_sites"], rows)
    [fact] = [fact for fact in _family(_normalize(exports), "call_site")
              if fact.payload["result"]["callee"]["display"] == "strlen"]
    assert fact.payload["result"]["in_loop"] is True


def test_unclassified_sink_is_published_and_ineligible(synthetic) -> None:
    [fact] = [fact for fact in _family(synthetic, "sink_site") if fact.payload["result"]["sink_class"] == "unclassified"]
    assert fact.payload["result"]["model"] == "RemoteFlowSinkFunction" and fact.payload["result"]["catalog_rule"] is None
    assert fact.payload["admissibility"]["direct_eligible"] is False
    assert fact.payload["admissibility"]["ineligibility_reasons"] == ["unclassified_sink"]
    assert synthetic.coverage_for("sink_site").status is c.Coverage.PARTIAL
    memcpy = [fact for fact in _family(synthetic, "sink_site") if fact.payload["result"]["catalog_rule"]
              == "cpp.sink.api.memcpy"]
    assert len(memcpy) == 2 and all(item.payload["admissibility"]["direct_eligible"] for item in memcpy)
    assert {item.payload["result"]["cwe_family"] for item in memcpy} == {"CWE-805"}


def test_several_sink_rows_for_one_key_keep_the_best_ranked_rule() -> None:
    exports = _exports()
    rows = _rows(exports["sink_sites"])
    extra = []
    for row in rows:
        if row["api"] == "memcpy":  # a model row competing with the API rule
            extra.append({**row, "model": "ArrayFunction.output"})
        if row["api"] == "send":    # a classified model row beats the unclassified one
            extra.append({**row, "model": "CommandExecutionFunction"})
    _set_rows(exports["sink_sites"], rows + extra)
    sinks = _family(_normalize(exports), "sink_site")
    assert {fact.payload["result"]["catalog_rule"] for fact in sinks if "memcpy" in fact.name} == {"cpp.sink.api.memcpy"}
    [send] = [fact for fact in sinks if fact.name.startswith("send")]
    assert send.payload["result"]["sink_class"] == "command_execution"
    assert send.payload["result"]["models"] == ["CommandExecutionFunction", "RemoteFlowSinkFunction"]
    assert len(sinks) == 7


def test_entry_points_are_classified_by_tier(synthetic) -> None:
    entries = {_at(fact): fact.payload["result"] for fact in _family(synthetic, "entry_point")}
    assert entries[(52, 20)]["source_class"] == "argv" and entries[(52, 20)]["catalog_rule"] == "cpp.source.model.argv"
    assert entries[(52, 20)]["exposure"] == {"basis": "codeql-model", "contract_id": None}
    # getenv: the API tier wins over the model+source_type tier.
    assert entries[(55, 16)]["catalog_rule"] == "cpp.source.api.getenv"
    assert entries[(55, 16)]["exposure"]["basis"] == "catalog-api"
    assert entries[(55, 16)]["enclosing_function"]["symbol"] == _symbol(synthetic, "main")


def test_max_paths_per_sink_keeps_the_shortest_and_records_omitted_paths() -> None:
    full = _normalize()
    [sink] = [fact for fact in _family(full, "sink_site") if _at(fact) == (45, 3)]
    to_sink = sorted((fact for fact in _family(full, "dataflow_path")
                      if fact.payload["result"]["sink"]["sink_site"] == sink.identity.value),
                     key=lambda fact: fact.payload["result"]["hop_count"])
    assert [fact.payload["result"]["hop_count"] for fact in to_sink] == [4, 5]
    assert [fact.payload["result"]["rank"] for fact in to_sink] == [0, 1]
    bounded = _normalize(settings=c.GraphSettings(max_paths_per_sink=1))
    kept = [fact for fact in _family(bounded, "dataflow_path")
            if fact.payload["result"]["sink"]["sink_site"] == sink.identity.value]
    assert [fact.identity.value for fact in kept] == [to_sink[0].identity.value]
    assert kept[0].payload["result"]["source"]["source_class"] == "environment"
    assert any(gap.startswith("omitted_paths: 1 ") for gap in kept[0].payload["gaps"])
    row = bounded.coverage_for("dataflow_path")
    assert row.status is c.Coverage.PARTIAL and row.counts["omitted_paths"] == 1
    assert any(gap.startswith(f"omitted_paths: sink {sink.identity.value}: 1 ") for gap in row.gaps)


def test_paths_carry_ordered_resolvable_steps_guards_and_their_source(synthetic) -> None:
    [path] = [fact for fact in _family(synthetic, "dataflow_path")
              if fact.payload["result"]["source"]["source_class"] == "environment"]
    result = path.payload["result"]
    assert [step["role"] for step in result["steps"]] == ["source", "step", "step", "call", "sink"]
    assert [(step["location"]["start_line"], step["location"]["start_column"]) for step in result["steps"]] == [
        (55, 16), (55, 11), (58, 32), (41, 49), (45, 20)]
    assert [step["location"]["path"] for step in result["steps"]] == [TARGET_PATH] * 5
    assert result["steps"][-1]["symbol"] == _symbol(synthetic, "copy_unchecked")
    assert result["steps"][0]["symbol"] == _symbol(synthetic, "main")
    assert result["call_depth"] == 1 and result["truncated_steps"] is False and result["selection"] == "shortest-k"
    guards = {fact.identity.value for fact in _family(synthetic, "guard_fact")
              if fact.payload["result"]["sink"]["sink_site"] == result["sink"]["sink_site"]}
    assert set(result["guards"]) == guards and len(guards) == 2
    assert path.payload["admissibility"]["direct_eligible"] is True
    assert c.mapped_predicates("dataflow_path", result) == c.GRAPH_FACT_PREDICATES[c.Family.DATAFLOW_PATH]


def test_max_path_steps_truncates_and_marks_the_path_partial() -> None:
    result = _normalize(settings=c.GraphSettings(max_path_steps=3))
    paths = _family(result, "dataflow_path")
    long = [fact for fact in paths if fact.payload["result"]["truncated_steps"]]
    assert long and all(len(fact.payload["result"]["steps"]) == 3 for fact in long)
    assert all(fact.payload["coverage_status"] == "partial" for fact in long)
    assert all(fact.payload["result"]["steps"][-1]["role"] == "sink" for fact in long)
    assert result.coverage_for("dataflow_path").counts["truncated_steps"] == len(long)


def test_max_neighbors_per_function_truncates_deterministically_by_identity() -> None:
    full = _family(_normalize(), "call_site")
    main = _symbol(_normalize(), "main")
    in_main = sorted(fact.identity.value for fact in full if fact.payload["result"]["caller"]["symbol"] == main)
    assert len(in_main) == 8
    settings = c.GraphSettings(max_neighbors_per_function=3)
    exports = _exports()
    random.Random(5).shuffle(exports["call_sites"]["rows"])
    for result in (_normalize(settings=settings), _normalize(exports, settings=settings)):
        kept = [fact for fact in _family(result, "call_site") if fact.payload["result"]["caller"]["symbol"] == main]
        assert sorted(fact.identity.value for fact in kept) == in_main[:3]
        assert all(fact.payload["coverage_status"] == "partial" and any(
            gap.startswith("truncated_neighbors") for gap in fact.payload["gaps"]) for fact in kept)
        assert result.coverage_for("call_site").counts["truncated_neighbors"] == 5


def test_guards_publish_one_none_fact_per_unguarded_sink_with_the_contract_identity(synthetic) -> None:
    sinks = {fact.identity.value: fact for fact in _family(synthetic, "sink_site")}
    none = [fact for fact in _family(synthetic, "guard_fact") if fact.payload["result"]["guard_state"] == "none"]
    assert len(none) == 4 and len({fact.payload["result"]["sink"]["sink_site"] for fact in none}) == 4
    for fact in none:
        sink = sinks[fact.payload["result"]["sink"]["sink_site"]]
        native = c.none_guard_native(SCOPE["scope_id"], sink.identity.value, sink.location.path,
                                     sink.location.start_byte, sink.location.end_byte)
        assert fact.identity == c.fact_identity(c.Family.GUARD_FACT, SNAPSHOT, native)
        assert fact.payload["result"]["condition"] is None and fact.location == sink.location
    [dominating] = [fact for fact in _family(synthetic, "guard_fact")
                    if fact.payload["result"]["guard_state"] == "dominating" and _at(fact) == (33, 7)]
    assert dominating.payload["result"]["polarity"] == "true_branch"
    assert dominating.payload["result"]["constrains_sink_operand"] is True
    comparison = dominating.payload["result"]["comparison"]
    assert {key: comparison[key] for key in ("operator", "bound_display")} == {"operator": "<", "bound_display": "64"}
    assert dominating.payload["admissibility"]["direct_eligible"] is True


def _operands(fact: c.GraphFact) -> dict[str, dict[str, Any]]:
    return {item["role"]: item for item in fact.payload["result"]["comparison"]["operands"]}


def _guard_at(result, line: int, column: int, state: str = "dominating") -> c.GraphFact:
    [fact] = [item for item in _family(result, "guard_fact")
              if item.payload["result"]["guard_state"] == state and _at(item) == (line, column)]
    return fact


def test_guard_operands_carry_kind_value_and_text_sliced_from_the_accepted_bytes(synthetic) -> None:
    dominating = _guard_at(synthetic, 33, 7)
    operands = _operands(dominating)
    assert [(role, item["kind"], item["value"], item["text"]) for role, item in operands.items()] == [
        ("lhs", "variable", None, "len"), ("rhs", "constant", 64, "64")]
    for item in operands.values():
        location = item["location"]
        assert SOURCE_BYTES[location["start_byte"]:location["end_byte"]].decode() == item["text"]
        assert location["path"] == TARGET_PATH
    assert dominating.payload["result"]["destination"] == {"object_bytes": None}
    assert "capacity_relation" not in dominating.payload["result"]
    none = [fact for fact in _family(synthetic, "guard_fact") if fact.payload["result"]["guard_state"] == "none"]
    assert all(fact.payload["result"]["comparison"] is None for fact in none)


def test_a_macro_operand_reported_at_the_expansion_site_has_no_text_and_a_named_gap(synthetic) -> None:
    macro = _guard_at(synthetic, 36, 7)
    operands = _operands(macro)
    assert operands["lhs"]["text"] == "len" and operands["rhs"]["text"] is None
    assert (operands["rhs"]["kind"], operands["rhs"]["value"]) == ("constant", 64)
    assert any(gap.startswith("operand_text_unavailable: rhs") for gap in macro.payload["gaps"])


def test_destination_object_bytes_is_a_plain_fact_and_unknown_is_null() -> None:
    exports = _exports()
    rows = _rows(exports["guards"])
    for row in rows:
        if row["condition_start_line"] == 33 and row["guard_state"] == "dominating":
            row["destination_object_bytes"] = 16
    _set_rows(exports["guards"], rows)
    result = _normalize(exports)
    assert _guard_at(result, 33, 7).payload["result"]["destination"] == {"object_bytes": 16}
    assert _guard_at(result, 36, 7).payload["result"]["destination"] == {"object_bytes": None}


def test_operand_text_is_bounded_and_the_truncation_is_named(monkeypatch) -> None:
    monkeypatch.setattr("appsec_review.graph.normalize.GUARD_OPERAND_TEXT_LIMIT", 2)
    fact = _guard_at(_normalize(), 33, 7)
    assert _operands(fact)["lhs"]["text"] == "le"
    assert any(gap.startswith("operand_text_truncated: lhs") for gap in fact.payload["gaps"])


@pytest.mark.parametrize("column,value", [("lhs_kind", "register"), ("rhs_kind", ""), ("rhs_value", "0x40"),
                                          ("destination_object_bytes", -7)])
def test_an_unknown_operand_vocabulary_or_size_is_not_published_and_named(column: str, value: Any) -> None:
    exports = _exports()
    rows = _rows(exports["guards"])
    for row in rows:
        if row["condition_start_line"] == 33 and row["guard_state"] == "dominating":
            row[column] = value
    _set_rows(exports["guards"], rows)
    result = _normalize(exports)
    assert not [fact for fact in _family(result, "guard_fact") if _at(fact) == (33, 7)
                and fact.payload["result"]["guard_state"] == "dominating"]
    assert any(gap.startswith("unknown_guard_vocabulary") for gap in result.coverage_for("guard_fact").gaps)


def test_the_contract_rejects_an_unknown_kind_and_any_extra_key_on_an_operand(synthetic) -> None:
    result = copy.deepcopy(dict(_guard_at(synthetic, 33, 7).payload["result"]))
    c.validate_guard_result(result)
    result["comparison"]["operands"][0]["kind"] = "register"
    with pytest.raises(c.GraphContractError, match="closed vocabulary"):
        c.validate_guard_result(result)
    result["comparison"]["operands"][0]["kind"] = "variable"
    result["comparison"]["operands"][0]["relation"] = "references_capacity"
    with pytest.raises(c.GraphContractError, match="operand keys"):
        c.validate_guard_result(result)


def test_post_dominating_only_guard_never_becomes_dominating() -> None:
    exports = _exports()
    rows = _rows(exports["guards"])
    for row in rows:
        if row["guard_state"] == "dominating" and row["condition_start_line"] == 33:
            row["guard_state"], row["polarity"] = "post_dominating_only", "unknown"
    _set_rows(exports["guards"], rows)
    guards = _family(_normalize(exports), "guard_fact")
    [fact] = [fact for fact in guards if _at(fact) == (33, 7) and fact.payload["result"]["sink"]["sink_site"]
              and fact.payload["result"]["guard_state"] != "non_dominating"]
    assert fact.payload["result"]["guard_state"] == "post_dominating_only"
    assert any(gap.startswith("post_dominating_only") for gap in fact.payload["gaps"])
    assert not [item for item in guards if _at(item) == (33, 7) and item.payload["result"]["guard_state"] == "dominating"]


def test_max_guards_per_sink_bounds_by_state_then_identity() -> None:
    result = _normalize(settings=c.GraphSettings(max_guards_per_sink=1))
    [sink] = [fact for fact in _family(result, "sink_site") if _at(fact) == (45, 3)]
    kept = [fact for fact in _family(result, "guard_fact") if fact.payload["result"]["sink"]["sink_site"]
            == sink.identity.value]
    assert [fact.payload["result"]["guard_state"] for fact in kept] == ["non_dominating"]
    assert kept[0].payload["coverage_status"] == "partial"
    assert result.coverage_for("guard_fact").status is c.Coverage.PARTIAL


def test_range_facts_publish_unknown_bounds_and_sign_changing_conversions(synthetic) -> None:
    ranges = {_at(fact): fact for fact in _family(synthetic, "range_fact")}
    unknown = ranges[(45, 20)].payload["result"]
    assert unknown["interval"] == {"lower": "unknown", "upper": "unknown"}
    assert unknown["sign_change"] is True and unknown["conversions"][0]["kind"] == "sign_change"
    assert unknown["conversions"][0]["location"]["start_column"] == 20
    assert unknown["type"] == {"display": "int", "signed": True, "bits": 32} and unknown["operand_index"] == 2
    assert ranges[(34, 22)].payload["result"]["interval"] == {"lower": "unknown", "upper": 63}
    assert ranges[(43, 9)].payload["result"]["interval"] == {"lower": 0, "upper": 0}
    pointer = ranges[(15, 66)].payload["result"]
    assert pointer["applicability"] == "not_applicable" and pointer["interval"] is None
    assert len(ranges) == 7  # one per sink operand, unknown included


def test_flow_summaries_name_the_function_symbol_and_opaque_calls(synthetic) -> None:
    summaries = {fact.payload["result"]["function"]["display"]: fact for fact in _family(synthetic, "flow_summary")}
    checked = summaries["copy_checked"].payload["result"]
    assert checked["function"]["symbol"] == _symbol(synthetic, "copy_checked")
    assert checked["opaque_calls"] == ["memcpy"] and checked["k_limited"] is False
    assert [pair["to"]["kind"] for pair in checked["pairs"]] == ["parameter_deref", "sink", "sink"]
    assert summaries["copy_checked"].payload["admissibility"]["direct_eligible"] is True


def test_missing_exports_make_their_families_unavailable() -> None:
    exports = _exports()
    del exports["guards"]
    result = _normalize(exports)
    assert result.coverage_for("guard_fact").status is c.Coverage.UNAVAILABLE
    assert not _family(result, "guard_fact")
    assert result.coverage_for("sink_site").status is not c.Coverage.UNAVAILABLE
    empty = _normalize({})
    assert not empty.facts and not empty.symbols and not empty.relations
    assert {row.status for row in empty.coverage} == {c.Coverage.UNAVAILABLE}
    assert all(any(gap.startswith("export_unavailable") for gap in row.gaps) for row in empty.coverage)


def test_truncated_export_makes_the_family_partial() -> None:
    exports = _exports()
    exports["call_sites"]["truncated"] = True
    exports["call_sites"]["row_count"] = 40
    row = _normalize(exports).coverage_for("call_site")
    assert row.status is c.Coverage.PARTIAL and any(gap.startswith("export_truncated: call_sites") for gap in row.gaps)


def test_no_codeql_element_id_survives_into_any_payload(synthetic) -> None:
    text = re.sub(r"[0-9a-f]{64}", "<sha256>", synthetic.to_json().decode())
    assert not re.search(r'"(id|label|entity)"\s*:', text)
    assert not re.search(r"(?<![0-9a-f])\d{5,}(?![0-9a-f])", text)
    assert not re.search(r"@\d", text)


def test_native_recording_normalizes_against_its_build_fixture() -> None:
    provenance = json.loads((NATIVE / "provenance.json").read_text(encoding="utf-8"))
    root = (NATIVE / provenance["source_root"]).resolve()
    sources = {path.name: SourceFile.from_bytes(path.read_bytes()) for path in root.iterdir()
               if path.suffix in {".c", ".cpp", ".h"}}
    scope = {"scope_id": "codeql-unit-native", "language": "cpp", "build_unit_id": "native", "root": "."}
    result = _normalize(_exports(NATIVE), scope=scope, sources=sources)
    assert result.facts and all(row.status is not c.Coverage.UNAVAILABLE for row in result.coverage)
    for fact in result.facts:
        fact.to_entity()
    assert result.to_json() == _normalize(_exports(NATIVE), scope=scope, sources=sources).to_json()


# --------------------------------------------------------------------------- catalog


def test_catalog_loads_validates_and_rejects_contract_drift() -> None:
    assert CATALOG.version == c.CATALOG_SCHEMA and CATALOG.language("c/c++") is CATALOG.language("cpp")
    assert CATALOG.sha256 == __import__("hashlib").sha256(CATALOG_PATH.read_bytes()).hexdigest()
    document = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    drifted = copy.deepcopy(document)
    drifted["attacker_reachable_sources"].remove("ipc")
    with pytest.raises(CatalogError, match="attacker_reachable"):
        parse_catalog(json.dumps(drifted).encode())
    duplicate = copy.deepcopy(document)
    duplicate["languages"]["cpp"]["sinks"].append({**duplicate["languages"]["cpp"]["sinks"][0],
                                                   "rule_id": "cpp.sink.api.strcpy2"})
    with pytest.raises(CatalogError, match="duplicate"):
        parse_catalog(json.dumps(duplicate).encode())
    with pytest.raises(CatalogError, match="schema"):
        parse_catalog(json.dumps({**document, "extra": 1}).encode())
    with pytest.raises(CatalogError, match="language"):
        CATALOG.language("python")


@pytest.mark.parametrize(("row", "expected"), [
    ({"api": "memcpy", "declared_in": "string.h", "argument_index": 2, "model": "api"}, ("memory_write", 1)),
    ({"api": "memcpy", "declared_in": "other.h", "argument_index": 2, "model": "api"}, ("unclassified", 4)),
    ({"api": "memcpy", "declared_in": "string.h", "argument_index": 0, "model": "ArrayFunction.output"},
     ("memory_write", 3)),
    ({"api": "printf", "declared_in": "stdio.h", "argument_index": 0, "model": "FormattingFunction"},
     ("format_string", 3)),
    ({"api": "send", "declared_in": "socket.h", "argument_index": 1, "model": "RemoteFlowSinkFunction"},
     ("unclassified", 4)),
])
def test_sink_classification_tiers(row, expected) -> None:
    result = CATALOG.language("cpp").classify_sink(row)
    assert (result.klass, result.tier) == expected


@pytest.mark.parametrize(("row", "expected"), [
    ({"api": "getenv", "declared_in": "stdlib.h", "index": -1, "model": "LocalFlowSource",
      "source_type": "an environment variable"}, ("environment", "cpp.source.api.getenv")),
    ({"api": "", "declared_in": "", "index": 1, "model": "LocalFlowSource", "source_type": "a command-line argument"},
     ("argv", "cpp.source.model.argv")),
    ({"api": "", "declared_in": "", "index": 0, "model": "LocalFlowSource", "source_type": "something else"},
     ("local_user", "cpp.source.model.local")),
    ({"api": "", "declared_in": "", "index": 0, "model": "FlowSource", "source_type": ""}, ("unclassified", None)),
])
def test_source_classification_tiers(row, expected) -> None:
    result = CATALOG.language("cpp").classify_source(row)
    assert (result.klass, result.rule_id) == expected


# --------------------------------------------------------------------------- downstream chunks (C4, C6)


def _clangd_symbol(name: str, line: int, column: int) -> dict[str, Any]:
    identity = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"producer": "clangd", "name": name}).value
    return {"identity": identity, "kind": "symbol", "name": name,
            "payload": {"producer": "clangd", "definition": {"path": TARGET_PATH, "line": line, "column": column,
                                                             "end_line": line, "end_column": column + len(name)}}}


def test_cross_check_agrees_on_the_defining_name_span_and_call_span(synthetic) -> None:
    caller, callee = _clangd_symbol("main", 52, 5), _clangd_symbol("copy_checked", 32, 6)
    calls = {"kind": "CALLS", "source_id": caller["identity"], "target_id": callee["identity"],
             "payload": {"occurrences": 1, "locations": [{"path": TARGET_PATH, "line": 56, "column": 3}]}}
    shard = SecondaryShard(c.Producer.CLANGD, "analysis", "clangd-synthetic", "b" * 64, (caller, callee), (calls,))
    result = cross_check(synthetic.facts, CrossCheckInputs(clangd=(shard,)), target_snapshot=SNAPSHOT,
                         scope=synthetic.facts[0].payload["scope"], sources=SOURCES, graph_symbols=synthetic.symbols)
    same_as = {(r.source_id, r.target_id): r.exact for r in result.relations if r.kind is RelationKind.SAME_AS}
    assert same_as[(_symbol(synthetic, "copy_checked"), callee["identity"])] is True
    assert same_as[(_symbol(synthetic, "main"), caller["identity"])] is True
    [call] = [fact for fact in result.facts if fact.family is c.Family.CALL_SITE
              and fact.payload["result"]["callee"]["display"] == "copy_checked"]
    assert call.payload["cross_check"]["state"] == "agree" and call.payload["admissibility"]["direct_eligible"]
    others = [fact for fact in result.facts if fact.identity != call.identity]
    assert {fact.payload["cross_check"]["state"] for fact in others} == {"not_covered"}
    assert not [fact for fact in result.facts if fact.payload["result"].get("callee", {}).get("dispatch")
                == "secondary_only"]
    for fact in result.facts:
        fact.to_entity()


def _sarif(line: int, column: int, end_line: int, end_column: int, ordinal: int) -> dict[str, Any]:
    return {"ordinal": ordinal, "code_flow": 0, "thread_flow": 0, "message": "step",
            "location": {"path": TARGET_PATH, "file_sha256": SOURCE.sha256, "start_line": line, "end_line": end_line,
                         "start_column": column, "end_column": end_column, "confidence": 1.0, "ambiguous": False}}


def test_correlation_bridges_a_sarif_flow_onto_the_normalized_path(synthetic) -> None:
    # SARIF end columns are exclusive: getenv(...) → atoi(...) → m → len parameter → memcpy sink expression.
    flow = [_sarif(55, 16, 55, 35, 0), _sarif(55, 11, 55, 36, 1), _sarif(58, 32, 58, 33, 2),
            _sarif(41, 49, 41, 56, 3), _sarif(45, 3, 45, 24, 4)]
    observation = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"codeql": "env"}).value
    rows = [{"identity": observation, "kind": "tool_observation", "payload": {"producer": "codeql", "flows": flow}}]
    result = correlate(synthetic.facts, rows, sources=SOURCES)
    [flow_result] = result.correlations
    [path] = [fact for fact in _family(synthetic, "dataflow_path")
              if fact.payload["result"]["source"]["source_class"] == "environment"]
    assert flow_result.state is CorrelationState.BRIDGED and flow_result.path == path.identity.value
    [relation] = [r for r in result.relations if r.kind is RelationKind.DERIVED_FROM]
    assert (relation.source_id, relation.target_id, relation.exact) == (path.identity.value, observation, True)


def _stage(tmp_path: Path, normalized) -> RetrievalCore:
    run_root = tmp_path / "runs" / RUN_ID
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / TARGET_PATH).write_bytes(SOURCE_BYTES)
    identities: list[IndexIdentity] = []
    for shard in normalized.shards():
        shard_id = f"{normalized.scope_id}.{shard.family.value}"
        fingerprint = index_fingerprint(name=c.GRAPH_INDEX, target_snapshot=SNAPSHOT,
                                        producer_artifacts=[{"shard": shard_id}], tool_identity={"tool": "c3"},
                                        parser_identity="c3/1", normalizer_identity=c.NORMALIZE_RULE,
                                        mapping_identity="c3/1")
        location = run_root / "data" / "indices" / c.GRAPH_INDEX / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(location, name=c.GRAPH_INDEX, fingerprint=fingerprint, target_snapshot=SNAPSHOT,
                               shard_id=shard_id)
        for entity in shard.entities:
            builder.add_entity(entity)
        for relation in shard.relations:
            builder.add_relation(relation)
        builder.add_coverage(shard.coverage.area, shard.coverage.status.value, shard.coverage.gap)
        identities.append(IndexIdentity(
            c.GRAPH_INDEX, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
            location.relative_to(run_root).as_posix(),
            {"job": "job_code_graph_index", "family": shard.family.value, "scope_id": normalized.scope_id}, (),
            shard_id))
    manifest = run_root / "data" / "indices" / "manifests" / "graph-c3.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    artifact = {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest),
                "size_bytes": manifest.stat().st_size}
    handoff = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001" / "handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED", "job_id": "fixture",
                          "attempt_id": "attempt_0001", "artifacts": [artifact], "outputs": {}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": artifact["path"], "manifest_sha256": artifact["sha256"]})
    return RetrievalCore(tmp_path / "runs", RUN_ID)


def test_query_code_graph_reads_normalized_shards_end_to_end(tmp_path, synthetic) -> None:
    core = _stage(tmp_path, synthetic)
    ids = lambda response: [row["identity"] for row in response["results"]]
    copy_unchecked = _symbol(synthetic, "copy_unchecked")

    callers = core.query_code_graph(mode="callers", subject=copy_unchecked)
    expected_calls = sorted(fact.identity.value for fact in _family(synthetic, "call_site")
                            if fact.payload["result"]["callee"]["symbol"] == copy_unchecked)
    assert len(expected_calls) == 2
    assert [row["identity"] for row in callers["results"] if "closure_role" not in row] == expected_calls
    assert [row["payload"]["result"]["callee"]["dispatch"] for row in callers["results"]
            if row.get("closure_role")] == ["unresolved_indirect"]

    sinks = core.query_code_graph(mode="sinks", subject=copy_unchecked)
    assert sorted((row["location"]["start_line"], row["payload"]["result"]["sink_class"]) for row in
                  sinks["results"]) == [(43, "memory_write"), (45, "memory_write")]

    [sink] = [fact for fact in _family(synthetic, "sink_site") if _at(fact) == (45, 3)]
    paths = core.query_code_graph(mode="paths", subject=sink.identity.value)
    assert [row["payload"]["result"]["hop_count"] for row in paths["results"]] == [4, 5]
    assert [step["location"]["path"] for step in paths["results"][0]["payload"]["result"]["steps"]] == [TARGET_PATH] * 5
    by_step = core.query_code_graph(mode="paths", subject=copy_unchecked)
    assert set(ids(by_step)) >= set(ids(paths))

    guards = core.query_code_graph(mode="guards", subject=sink.identity.value)
    assert [row["payload"]["result"]["guard_state"] for row in guards["results"]] == ["non_dominating", "none"]
    assert any(f"coverage graph:{SCOPE['scope_id']}:guard_fact: partial" in gap for gap in guards["coverage_gaps"])

    ranges = core.query_code_graph(mode="ranges", subject=sink.identity.value)
    assert [row["payload"]["result"]["interval"] for row in ranges["results"]] == [
        {"lower": "unknown", "upper": "unknown"}]
    summary = core.query_code_graph(mode="summary", subject=copy_unchecked)
    assert [row["payload"]["result"]["function"]["symbol"] for row in summary["results"]] == [copy_unchecked]
    for row in [*callers["results"], *sinks["results"], *paths["results"], *guards["results"]]:
        assert core.find(identity=row["identity"], limit=1)["results"][0]["identity"] == row["identity"]
    entry = next(fact for fact in _family(synthetic, "entry_point") if _at(fact) == (55, 16))
    from_entry = core.query_code_graph(mode="paths", subject=entry.identity.value, source_class="environment")
    assert len(from_entry["results"]) == 1
    assert asdict(sink.location)["path"] == TARGET_PATH
