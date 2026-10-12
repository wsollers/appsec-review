from __future__ import annotations

import copy
import itertools

import pytest

from appsec_review.graph import contract as c
from appsec_review.retrieval.index import INDEX_NAMES
from appsec_review.retrieval.model import EntityKind, LogicalIdentity, RelationKind, SourceLocation
from appsec_review.review.models import Predicate

SNAPSHOT = "snapshot-1"
SHA = "a" * 64

NATIVE = {
    c.Family.CALL_SITE: {"scope_id": "s", "caller_symbol": "asr:symbol:" + SHA, "path": "a.c", "start_byte": 1,
                         "end_byte": 9, "callee_name": "memcpy"},
    c.Family.SINK_SITE: {"scope_id": "s", "path": "a.c", "start_byte": 1, "end_byte": 9, "sink_class": "memory_write",
                         "argument_index": 2},
    c.Family.ENTRY_POINT: {"scope_id": "s", "path": "a.c", "start_byte": 1, "end_byte": 9, "source_class": "remote"},
    c.Family.FLOW_SUMMARY: {"scope_id": "s", "function_symbol": "asr:symbol:" + SHA, "rule_version": "graph-normalize/1"},
    c.Family.DATAFLOW_PATH: {"scope_id": "s", "source_identity": "asr:entry_point:" + SHA,
                             "sink_identity": "asr:sink_site:" + SHA, "step_locations_sha256": SHA},
    c.Family.GUARD_FACT: {"scope_id": "s", "sink_identity": "asr:sink_site:" + SHA, "condition_path": "a.c",
                          "condition_start_byte": 3, "condition_end_byte": 7},
    c.Family.RANGE_FACT: {"scope_id": "s", "sink_identity": "asr:sink_site:" + SHA, "operand_index": 1},
}


def _location(*, ambiguous: bool = False, confidence: float = 1.0) -> SourceLocation:
    return SourceLocation(SNAPSHOT, "a.c", SHA, 1, 9, 1, 1, 2, 10, {}, "codeql-location-exact", confidence, ambiguous)


def _payload(family: c.Family = c.Family.SINK_SITE, **overrides) -> dict:
    result = {c.Family.SINK_SITE: {"sink_class": "memory_write"},
              c.Family.ENTRY_POINT: {"source_class": "remote"},
              c.Family.DATAFLOW_PATH: {"source": {"source_class": "remote"}, "sink": {"sink_class": "memory_write"}},
              }.get(family, {})
    payload = {
        "schema": c.GRAPH_FACT_SCHEMA, "family": family.value,
        "producer": {"name": "codeql-export", "tool_version": "2.27.0", "export_pack_sha256": SHA,
                     "catalog_version": c.CATALOG_SCHEMA, "rule_version": c.NORMALIZE_RULE},
        "scope": {"scope_id": "s", "language": "c/c++", "build_unit_id": "bu", "component_id": "cmp"},
        "exact": True, "coverage_status": "complete", "gaps": [],
        "cross_check": {"rule": c.CROSS_CHECK_RULE, "state": "not_covered", "producers": []},
        "result": result, "upstream": [{"index": "observations", "shard_id": "codeql-cpp", "sha256": SHA}],
        "authority": c.AUTHORITY,
    }
    payload.update(overrides)
    payload["admissibility"] = c.admissibility(payload)
    return payload


@pytest.mark.parametrize("enum", [c.Family, c.Mode, c.Dispatch, c.SinkClass, c.SourceClass, c.GuardState,
                                  c.GuardPolarity, c.CrossCheckState, c.Coverage, c.Producer])
def test_vocabularies_are_closed_unique_and_lowercase(enum) -> None:
    values = [member.value for member in enum]
    assert len(values) == len(set(values)) and all(value == value.lower() for value in values)
    with pytest.raises(ValueError):
        enum("not-a-member")


def test_contract_names_match_the_strategy_document() -> None:
    assert [f.value for f in c.Family] == ["call_site", "sink_site", "entry_point", "flow_summary", "dataflow_path",
                                           "guard_fact", "range_fact"]
    assert {f.value for f in c.Family} <= {k.value for k in EntityKind}
    assert RelationKind.GUARDS.value == "GUARDS" and c.GRAPH_INDEX in INDEX_NAMES
    assert c.QUERY_CODE_GRAPH == "query_code_graph"
    assert set(c.MODE_SUBJECT_KINDS) == set(c.Mode) == set(c.MODE_FAMILY)
    assert c.ATTACKER_REACHABLE_SOURCES == {"remote", "local_user", "argv", "environment", "file", "ipc"}


def test_fact_predicates_cover_exactly_six_families_with_predicate_values() -> None:
    assert set(c.GRAPH_FACT_PREDICATES) == set(c.Family) - {c.Family.FLOW_SUMMARY}
    assert all(values and values <= set(Predicate) for values in c.GRAPH_FACT_PREDICATES.values())


@pytest.mark.parametrize("family", list(c.Family))
def test_identities_are_deterministic_and_change_with_every_native_field(family) -> None:
    native = NATIVE[family]
    first = c.fact_identity(family, SNAPSHOT, native)
    assert first == c.fact_identity(family, SNAPSHOT, dict(reversed(list(native.items()))))
    assert first.kind is EntityKind(family.value)
    assert c.fact_identity(family, "snapshot-2", native) != first
    for name in native:
        changed = dict(native)
        changed[name] = changed[name] + 1 if isinstance(changed[name], int) else str(changed[name]) + "x"
        assert c.fact_identity(family, SNAPSHOT, changed) != first, name


def test_identity_rejects_missing_extra_and_empty_fields() -> None:
    native = dict(NATIVE[c.Family.SINK_SITE])
    with pytest.raises(c.GraphContractError):
        c.fact_identity(c.Family.SINK_SITE, SNAPSHOT, {**native, "clangd_usr": "c:@F@x"})
    with pytest.raises(c.GraphContractError):
        c.fact_identity(c.Family.SINK_SITE, SNAPSHOT, {k: v for k, v in native.items() if k != "argument_index"})
    with pytest.raises(c.GraphContractError):
        c.fact_identity(c.Family.SINK_SITE, SNAPSHOT, {**native, "path": ""})


def test_admissibility_truth_table_names_every_failed_condition() -> None:
    for exact, complete, state, classified in itertools.product((True, False), (True, False),
                                                                ("agree", "not_covered", "disagree", "partial"),
                                                                (True, False)):
        payload = _payload(
            c.Family.SINK_SITE, exact=exact, coverage_status="complete" if complete else "partial",
            gaps=[] if complete else ["path step bound reached"],
            cross_check={"rule": c.CROSS_CHECK_RULE, "state": state, "producers": []},
            result={"sink_class": "memory_write" if classified else "unclassified"})
        reasons = set(c.ineligibility_reasons(payload))
        expected = set()
        if not exact:
            expected.add("inexact_location")
        if not complete:
            expected.add("incomplete_coverage")
        if state not in {"agree", "not_covered"}:
            expected.add(f"cross_check_{state}")
        if not classified:
            expected.add("unclassified_sink")
        assert reasons == expected
        assert payload["admissibility"]["direct_eligible"] is (not expected)


def test_dataflow_path_classification_checks_both_ends() -> None:
    payload = _payload(c.Family.DATAFLOW_PATH, result={"source": {"source_class": "unclassified"}, "sink": {}})
    assert set(c.ineligibility_reasons(payload)) == {"unclassified_source", "unclassified_sink"}


def test_mapped_predicates_apply_the_attacker_reachable_condition() -> None:
    assert c.mapped_predicates("entry_point", {"source_class": "remote"}) == {Predicate.ATTACKER_INPUT_CONTROL}
    assert c.mapped_predicates("entry_point", {"source_class": "database"}) == frozenset()
    assert c.mapped_predicates("dataflow_path", {"source": {"source_class": "internal"}}) == {
        Predicate.SOURCE_TO_SINK_REACHABILITY}
    assert c.mapped_predicates("dataflow_path", {"source": {"source_class": "argv"}}) == {
        Predicate.SOURCE_TO_SINK_REACHABILITY, Predicate.ATTACKER_INPUT_CONTROL}
    assert c.mapped_predicates("flow_summary", {}) == frozenset()


def test_to_entity_rejects_forged_eligibility_and_inexact_location() -> None:
    identity = c.fact_identity(c.Family.SINK_SITE, SNAPSHOT, NATIVE[c.Family.SINK_SITE])
    entity = c.GraphFact(identity, "memcpy", _payload(), _location()).to_entity()
    assert entity.identity == identity and entity.payload["admissibility"]["direct_eligible"] is True
    forged = _payload(exact=False)
    forged["admissibility"] = {"rule": c.ADMISSIBILITY_RULE, "direct_eligible": True, "ineligibility_reasons": []}
    with pytest.raises(c.GraphContractError, match="admissibility"):
        c.GraphFact(identity, "memcpy", forged, _location()).to_entity()
    with pytest.raises(c.GraphContractError, match="exact"):
        c.GraphFact(identity, "memcpy", _payload(), _location(ambiguous=True)).to_entity()
    wrong_kind = LogicalIdentity.derive(EntityKind.RANGE_FACT, SNAPSHOT, {"x": 1})
    with pytest.raises(c.GraphContractError, match="kind"):
        c.GraphFact(wrong_kind, "memcpy", _payload(), _location()).to_entity()


def test_payload_shape_is_closed() -> None:
    payload = _payload()
    with pytest.raises(c.GraphContractError):
        c.validate_payload({**payload, "native_codeql_id": 7})
    incomplete = _payload(coverage_status="partial")
    with pytest.raises(c.GraphContractError, match="gaps"):
        c.validate_payload(incomplete)


def _export(**overrides) -> dict:
    document = {"schema": c.EXPORT_SCHEMA, "query_id": "cpp/graph/call-sites", "columns": ["caller", "callee"],
                "rows": [["a", "b"], ["a", "c"]], "row_count": 2, "truncated": False, "bqrs_sha256": SHA}
    document.update(overrides)
    return document


def test_export_validator_rejects_extra_keys_unsorted_rows_and_bad_counts() -> None:
    c.validate_export(_export())
    c.validate_export(_export(row_count=10, truncated=True))
    for bad in (_export(extra=1), _export(rows=[["a", "c"], ["a", "b"]]), _export(row_count=3),
                _export(rows=[["a"]], row_count=1), _export(bqrs_sha256="x"), _export(columns=["a", "a"])):
        with pytest.raises(c.GraphContractError):
            c.validate_export(copy.deepcopy(bad))


def test_settings_defaults_bounds_and_unknown_keys() -> None:
    settings = c.GraphSettings.from_mapping({})
    assert (settings.max_call_depth, settings.max_paths_per_sink, settings.export_timeout_seconds) == (3, 8, 1800)
    with pytest.raises(c.GraphContractError):
        c.GraphSettings.from_mapping({"max_call_depth": 5})
    with pytest.raises(c.GraphContractError):
        c.GraphSettings.from_mapping({"max_paths_per_sink": 0})
    with pytest.raises(c.GraphContractError):
        c.GraphSettings.from_mapping({"bogus": 1})
