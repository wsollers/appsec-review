from copy import deepcopy
from dataclasses import replace

import pytest

from appsec_review.review.behavior import graph_operations, opportunity_sites
from appsec_review.review.models import IntegrityError
from appsec_review.review.scope import SourceFile
from appsec_review.review.units import build_units, rank_units, select_hunts

from .support import ENTRY, PATH, SHA, SINK, SOURCE, Scope, collection, graph_row, tag_row


def test_same_site_is_one_operation_with_original_anchors():
    rows = [graph_row(), graph_row(ENTRY, "entry_point", "remote")]
    scope = Scope(graph=rows)
    operations, gaps = graph_operations(scope, limit=10)
    assert not gaps and len(operations) == 1
    operation = operations[0]
    assert operation.source_id == SOURCE and operation.classes == ("remote", "sql_query")
    assert operation.anchors == ((ENTRY, "entry_point"), (SINK, "sink"))
    assert operation.record()["authority"] == "routing_context"
    assert operation.record()["questions"]
    assert "public" not in repr(operation.record())
    assert graph_operations(Scope(graph=list(reversed(rows))), limit=10) == (operations, gaps)


def test_shardset_location_projection_uses_its_verified_scope_snapshot():
    row = graph_row()
    row["location"].pop("target_snapshot")
    operations, gaps = graph_operations(Scope(graph=[row]), limit=8)
    assert len(operations) == 1 and not gaps


@pytest.mark.parametrize("change", ["inexact", "partial", "disagree", "schema", "kind", "location",
                                    "unknown-class", "internal", "foreign-owner", "foreign-build", "unknown-source"])
def test_ineligible_facts_leave_a_named_gap_not_an_operation(change):
    row = graph_row()
    if change == "inexact":
        row["payload"]["exact"] = False
    elif change == "partial":
        row["payload"]["coverage_status"] = "partial"
    elif change == "disagree":
        row["payload"]["cross_check"]["state"] = "disagree"
    elif change == "schema":
        row["payload"]["schema"] = "unknown"
    elif change == "kind":
        row["payload"]["family"] = "entry_point"
    elif change == "location":
        row["location"] = None
    elif change == "unknown-class":
        row["payload"]["result"]["sink_class"] = "invented"
    elif change == "internal":
        row = graph_row(ENTRY, "entry_point", "internal")
    elif change == "foreign-owner":
        row["payload"]["scope"]["component_id"] = "other"
    elif change == "foreign-build":
        row["payload"]["scope"]["build_unit_id"] = "other"
    else:
        row["location"]["path"] = "missing.py"
    operations, gaps = graph_operations(Scope(graph=[row]), limit=10)
    assert not operations and len(gaps) == 1


@pytest.mark.parametrize("field,value", [("start_line", 0), ("end_line", 1), ("start_line", True),
                                       ("target_snapshot", "foreign")])
def test_invalid_accepted_source_identity_is_integrity_failure(field, value):
    row = graph_row()
    row["location"][field] = value
    with pytest.raises(IntegrityError, match="location"):
        graph_operations(Scope(graph=[row]), limit=10)


def test_missing_graph_and_record_limit_keep_fallback_explicit():
    scope = Scope()
    scope.available.remove("code_graph")
    assert graph_operations(scope, limit=1)[1][0].state == "missing"
    rows = [graph_row(), graph_row(ENTRY, "entry_point", "file", line=30)]
    operations, gaps = graph_operations(Scope(graph=rows), limit=1)
    assert len(operations) == 1 and gaps[0].state == "truncated"
    assert not graph_operations(Scope(graph=rows), limit=2)[1]


@pytest.mark.parametrize("limit", [0, -1, True])
def test_invalid_discovery_bound_rejected(limit):
    with pytest.raises(ValueError, match="limit"):
        graph_operations(Scope(), limit=limit)


@pytest.mark.parametrize("tag,basis", [
    ("lang:python", "declared"), ("gap:no-sast", "reported"), ("cwe:89", "derived"),
    ("func:data:sql-query", "declared"), ("func:data:sql-query", "reported"),
    ("asvs5:v1", "derived"), ("attack:t1059", "confirmed"),
])
def test_classification_or_uninvoked_labels_add_no_opportunity(tag, basis):
    assert not opportunity_sites([tag_row(tag, basis)])


def test_duplicate_labels_and_producers_do_not_multiply_sites():
    rows = [tag_row(), tag_row("surface:entry:file-input", identity="entry"), deepcopy(tag_row())]
    assert len(opportunity_sites(rows)) == 1
    rows.append(tag_row(line=30, identity="second"))
    assert len(opportunity_sites(rows)) == 2


@pytest.mark.parametrize("change", ["ambiguous", "missing-ref", "missing-location", "bad-span", "missing-hash"])
def test_invocation_without_source_binding_is_not_ranked(change):
    row = tag_row()
    if change == "ambiguous":
        row["payload"]["subject"]["component_ownership"] = "ambiguous"
    elif change == "missing-ref":
        row["payload"]["evidence"][0]["ref"] = ""
    elif change == "missing-location":
        row["payload"]["evidence"][0].pop("location")
    elif change == "bad-span":
        row["payload"]["evidence"][0]["location"]["end_line"] = 1
    else:
        row["payload"]["evidence"][0]["location"]["file_sha256"] = ""
    assert not opportunity_sites([row])


def test_operation_leads_and_whole_file_fallback_are_both_preserved():
    scope = Scope(graph=[graph_row()], extra_sources=(SourceFile("src/other.py", "asr:source_file:" + "9" * 64, "Python"),))
    operations, _ = graph_operations(scope, limit=10)
    leads = collection(20, 40)
    units = build_units(scope, leads, unit_max_files=10, operations=operations)
    named = next(unit for unit in units if unit.operation)
    fallback = next(unit for unit in units if unit.operation is None)
    assert named.paths == (PATH,) and named.source_ids == (SOURCE,)
    assert [lead.start_line for lead in named.leads] == [20]
    assert [lead.start_line for lead in fallback.leads] == [40]
    assert set(fallback.paths) == {PATH, "src/other.py"}
    assert {lead.observation_id for unit in units for lead in unit.leads} == set(lead.observation_id for lead in leads.leads)
    assert sum(len(unit.leads) for unit in units) == len(leads.leads)
    selected, gaps = select_hunts(rank_units(units), 1)
    assert selected[0].unit.operation is not None
    assert len(gaps) == 1 and "below_hunt_cutoff" in gaps[0].reason


def test_generated_boundary_is_routing_only_and_ambiguity_is_retained():
    scope = Scope(graph=[graph_row()])
    operations, _ = graph_operations(scope, limit=10)
    context = {"flow_id": "flow:1", "interaction": "datastore_query", "basis": "derived",
               "boundary_ids": ["tb:1"], "threat_ids": [], "authority": "routing_context"}
    units = build_units(scope, collection(), unit_max_files=10, operations=operations,
                        model_context={operations[0].operation_id: (context,)})
    assert next(unit for unit in units if unit.operation).trust_boundary_id == "tb:1"
    other = {**context, "boundary_ids": ["tb:2"]}
    units = build_units(scope, collection(), unit_max_files=10, operations=operations,
                        model_context={operations[0].operation_id: (context, other)})
    assert next(unit for unit in units if unit.operation).trust_boundary_id is None


def test_foreign_operation_cannot_be_attached_to_a_unit():
    scope = Scope(graph=[graph_row()])
    operations, _ = graph_operations(scope, limit=10)
    with pytest.raises(ValueError, match="exactly one"):
        build_units(scope, collection(), unit_max_files=10, operations=(replace(operations[0], component_id="other"),))


def test_ranking_counts_distinct_invoked_sites_and_unknown_coverage():
    scope = Scope(tags=[tag_row(), tag_row("lang:python", "declared"), tag_row(identity="duplicate")])
    unit, = build_units(scope, collection(), unit_max_files=10)
    score = next(signal for signal in unit.signals if signal.signal == "tag_density")
    assert score.value == 250
    scope.rows["security_tagging"] = [tag_row("gap:no-sast", "reported")]
    scope.states["security_tagging"] = "partial"
    unit, = build_units(scope, collection(), unit_max_files=10)
    assert next(signal for signal in unit.signals if signal.signal == "tag_density").value is None


def test_discovery_cap_does_not_remove_other_opportunities_in_the_same_file():
    scope = Scope(graph=[graph_row()], tags=[tag_row(), tag_row(line=30, identity="other-site")])
    operations, _ = graph_operations(scope, limit=1)
    units = build_units(scope, collection(), unit_max_files=10, operations=operations)
    fallback = next(unit for unit in units if unit.operation is None)
    assert next(signal.value for signal in fallback.signals if signal.signal == "tag_density") == 250


def test_operation_does_not_inherit_an_unrelated_files_priority():
    scope = Scope(graph=[graph_row()], extra_sources=(SourceFile("src/other.py", "asr:source_file:" + "9" * 64, "Python"),))
    scope.available.add("review_prioritization")
    scope.rows["review_prioritization"] = [
        {"identity": "asr:priority_item:" + "6" * 64, "kind": "priority_item",
         "location": {"path": PATH}, "payload": {"score": 0.1}},
        {"identity": "asr:priority_item:" + "7" * 64, "kind": "priority_item",
         "location": {"path": "src/other.py"}, "payload": {"score": 1.0}},
    ]
    operations, _ = graph_operations(scope, limit=10)
    units = build_units(scope, collection(20), unit_max_files=10, operations=operations)
    operation = next(unit for unit in units if unit.operation)
    fallback = next(unit for unit in units if not unit.operation)
    assert next(signal.value for signal in operation.signals if signal.signal == "lps") == 100
    assert next(signal.value for signal in fallback.signals if signal.signal == "lps") == 1000
