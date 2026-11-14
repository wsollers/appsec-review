from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from appsec_review.jobs.job_security_tagging.producers import collect_graph_facts
from appsec_review.jobs.job_security_tagging.taxonomy import validate_assignment

from .helpers import CannedIndexes, DATA, fact, payload_change, scope, shard, taxonomy


MAPPINGS = (
    ("entry_point", "remote", "surface:entry:remote-input"),
    ("entry_point", "argv", "surface:entry:cli"),
    ("entry_point", "environment", "surface:entry:env-config"),
    ("entry_point", "file", "surface:entry:file-input"),
    ("entry_point", "ipc", "surface:entry:local-ipc"),
    ("sink_site", "memory_read", "func:exec:unmanaged-memory"),
    ("sink_site", "memory_write", "func:exec:unmanaged-memory"),
    ("sink_site", "command_execution", "func:exec:process-spawn"),
    ("sink_site", "sql_query", "func:data:sql-query"),
    ("sink_site", "ldap_query", "func:data:ldap-query"),
    ("sink_site", "xml_external_entity", "func:data:parse-xml"),
    ("sink_site", "template_injection", "func:data:template-render"),
    ("sink_site", "regex_injection", "func:data:regex"),
    ("sink_site", "url_redirect", "func:net:redirect"),
    ("sink_site", "log_output", "func:telemetry:app-log"),
)


def collect(rows=(), *, indexes=None, components=None, rules=None, limit=100, **kwargs):
    vocabulary, pinned, _ = taxonomy()
    return collect_graph_facts(indexes or CannedIndexes(rows), scope(components), vocabulary,
                               rules or pinned, limit, **kwargs)


@pytest.mark.parametrize("family,klass,tag", MAPPINGS, ids=[item[1] for item in MAPPINGS])
def test_supported_mapping_preserves_exact_evidence(family, klass, tag):
    row = fact(klass, family=family, language="cpp" if klass.startswith("memory_") else "python")
    records, gaps = collect([row])
    assert not gaps
    assert len(records) == 1
    record = records[0]
    assert (record["tag"], record["basis"]) == (tag, "invoked")
    assert record["family"] == "code_facts" and not record["derived_from"]
    assert record["subject"]["component_id"] == "component:app"
    assert record["subject"]["kind"] == "source_span"
    evidence = record["evidence"][0]
    assert evidence["ref"] == row.identity
    assert evidence["location"] == row.location
    assert evidence["graph_producer"] == row.payload["producer"] == record["producer"]["graph_producer"]
    assert evidence["graph_scope"] == row.payload["scope"]
    assert evidence["graph_upstream"] == row.payload["upstream"]
    assert evidence["index_producer"] == shard()["producer"]
    assert evidence["index_sha256"] == shard()["sha256"]
    validate_assignment(taxonomy()[0], record)


@pytest.mark.parametrize("klass,family", [
    ("new-producer-class", "sink_site"), ("local_user", "entry_point"), ("database", "entry_point"),
    ("internal", "entry_point"), ("path_access", "sink_site"), ("allocation_size", "sink_site"),
    ("format_string", "sink_site"), ("integer_conversion", "sink_site"), ("crypto_misuse", "sink_site"),
    ("server_side_request", "sink_site"), ("code_injection", "sink_site"),
    ("deserialization", "sink_site"), ("html_output", "sink_site"), ("header_injection", "sink_site"),
    ("xpath_query", "sink_site"), ("unsafe_reflection", "sink_site"),
], ids=lambda value: value)
def test_unsupported_classes_never_guess_a_stronger_operation(klass, family):
    indexes = CannedIndexes([fact(klass, family=family)])
    records, gaps = collect(indexes=indexes)
    assert not records
    assert len(gaps) == 1 and "graph-capability:unmapped_class:" in gaps[0]
    assert not indexes.source_reads


@pytest.mark.parametrize("case", ["unclassified-source", "unclassified-sink", "disagree", "partial",
                                  "inexact", "incomplete"])
def test_ineligible_graph_facts_never_become_invoked(case):
    row = fact("unclassified", family="entry_point" if case == "unclassified-source" else "sink_site") \
        if case.startswith("unclassified") else fact()
    if case in {"disagree", "partial"}:
        row = payload_change(row, cross_check={**row.payload["cross_check"], "state": case})
    elif case == "inexact":
        row = payload_change(row, exact=False)
    elif case == "incomplete":
        row = payload_change(row, coverage_status="partial", gaps=["producer bound reached"])
    records, gaps = collect([row])
    assert not records
    assert any("ineligible_fact" in gap for gap in gaps)


@pytest.mark.parametrize("case", ["schema", "kind", "admissibility", "payload", "result", "producer",
                                  "identity", "native-id", "missing-location", "foreign-snapshot",
                                  "ambiguous", "confidence", "empty-span", "bool-byte", "argument",
                                  "scope", "language", "class", "path"])
def test_malformed_facts_have_named_gaps(case):
    row = fact()
    payload, location = deepcopy(row.payload), dict(row.location)
    if case == "schema":
        payload["schema"] = "foreign/1"
    elif case == "kind":
        payload["family"] = "call_site"
    elif case == "admissibility":
        payload["admissibility"]["direct_eligible"] = False
    elif case == "payload":
        payload = []
    elif case in {"result", "producer"}:
        payload[case] = None
    elif case == "identity":
        row = replace(row, identity=row.identity[:-1] + ("0" if row.identity[-1] != "0" else "1"))
    elif case == "native-id":
        row = replace(row, native_id="unknown")
    elif case == "missing-location":
        location = None
    elif case == "foreign-snapshot":
        location["target_snapshot"] = "foreign"
    elif case == "ambiguous":
        location["ambiguous"] = True
    elif case == "confidence":
        location["confidence"] = 0.5
    elif case == "empty-span":
        location["end_byte"] = location["start_byte"]
    elif case == "bool-byte":
        location["start_byte"] = False
    elif case == "argument":
        payload["result"]["argument_index"] = None
    elif case == "scope":
        payload["scope"]["component_id"] = []
    elif case == "language":
        payload["scope"]["language"] = None
    elif case == "class":
        payload["result"]["sink_class"] = []
    elif case == "path":
        location["path"] = "../outside"
    records, gaps = collect([replace(row, payload=payload, location=location)])
    assert not records
    assert len(gaps) == 1 and "malformed_fact" in gaps[0]


def test_remote_input_never_implies_http_or_deployment():
    records, gaps = collect([fact("remote", family="entry_point", language="cpp")])
    assert not gaps
    assert [record["tag"] for record in records] == ["surface:entry:remote-input"]
    assert records[0]["flow_role"] is None


def test_truthy_eligibility_is_not_boolean_evidence_eligibility():
    row = fact()
    payload = deepcopy(row.payload)
    payload["admissibility"]["direct_eligible"] = 1
    records, gaps = collect([replace(row, payload=payload)])
    assert not records and "ineligible_fact" in gaps[0]


@pytest.mark.parametrize("case", ["missing", "hash", "bytes", "lines", "columns"])
def test_source_must_resolve_exactly(case):
    row = fact()
    data = ValueError("indexed source is unavailable") if case == "missing" else DATA
    if case == "hash":
        data = b"different contents"
    elif case in {"bytes", "lines", "columns"}:
        field = {"bytes": "end_byte", "lines": "end_line", "columns": "end_column"}[case]
        row = replace(row, location={**row.location, field: row.location[field] + 1})
    records, gaps = collect(indexes=CannedIndexes([row], data=data))
    assert not records and gaps
    assert any(code in gaps[0] for code in ("source_unresolved", "source_span_mismatch", "malformed_fact"))


def test_unicode_multiline_exclusive_source_coordinates_are_preserved():
    data = "😀pre\nquery(user_input)".encode()
    row = fact(data=data)
    location = {**row.location, "start_line": 1, "start_column": 3, "start_byte": 4,
                "end_line": 2, "end_column": 18, "end_byte": len(data)}
    from appsec_review.graph.contract import fact_identity
    native = {"scope_id": "scope", "path": location["path"], "start_byte": 4,
              "end_byte": len(data), "sink_class": "sql_query", "argument_index": 0}
    identity = fact_identity("sink_site", scope().target_snapshot, native).value
    row = replace(row, identity=identity, native_id=identity, location=location)
    records, gaps = collect(indexes=CannedIndexes([row], data=data))
    assert not gaps and records[0]["evidence"][0]["location"] == location


def test_duplicate_sites_have_one_subject_and_keep_each_original_producer():
    one = fact()
    other = fact(scope_id="other-scope")
    other = replace(other, payload={**other.payload,
                                    "producer": {**other.payload["producer"], "tool_version": "2.25.0"}})
    indexes = CannedIndexes(groups=[(shard(shard_id="b", digest="d"), [other]),
                                   (shard(), [one, one])])
    records, gaps = collect(indexes=indexes)
    assert not gaps and len(records) == 2
    assert len({record["subject"]["logical_id"] for record in records}) == 1
    assert {record["evidence"][0]["ref"] for record in records} == {one.identity, other.identity}
    assert len(indexes.source_reads) == 1
    assert collect(indexes=CannedIndexes(groups=list(reversed(indexes.groups)))) == (records, gaps)


def test_multiple_capabilities_at_a_site_share_the_complete_subject():
    records, gaps = collect([fact(), fact("remote", family="entry_point")])
    assert not gaps and len(records) == 2
    assert {record["tag"] for record in records} == {"func:data:sql-query", "surface:entry:remote-input"}
    assert records[0]["subject"] == records[1]["subject"]


def test_conflicting_duplicate_fact_fails_closed_in_any_shard_order():
    row = fact()
    conflicting = replace(row, payload={**row.payload, "exact": False})
    groups = [(shard(), [row]), (shard(shard_id="other", digest="d"), [conflicting])]
    first = collect(indexes=CannedIndexes(groups=groups))
    assert first[0] == [] and "conflicting_fact" in first[1][0]
    assert collect(indexes=CannedIndexes(groups=list(reversed(groups)))) == first


def test_missing_graph_and_entity_cap_are_explicit_and_bounded():
    assert collect(indexes=CannedIndexes(missing=True))[1] == [
        "graph-capability:missing_graph: accepted graph index is unavailable"]
    indexes = CannedIndexes([fact(), fact(start=1)])
    records, gaps = collect(indexes=indexes, limit=1)
    assert len(records) == 1 and any("entity_bound" in gap for gap in gaps)
    assert indexes.reads[0][1:] == (("entry_point", "sink_site"), 1)


@pytest.mark.parametrize("ownership", ["owned", "shared", "ambiguous", "unowned", "disagree"])
def test_component_ownership_never_guesses(ownership):
    components = [
        {"component_id": "component:app", "root": ".", "ecosystem": "python", "logical_id": "a"},
        {"component_id": "component:other", "root": "src", "ecosystem": "python", "logical_id": "b"}]
    row = fact(component="component:other")
    if ownership == "shared":
        components[0]["root"] = "src"
    elif ownership == "ambiguous":
        components[0]["root"] = "src"
        components[0]["ecosystem"] = components[1]["ecosystem"] = "ruby"
    elif ownership == "unowned":
        components = []
    elif ownership == "disagree":
        row = fact(component="component:app")
    records, gaps = collect([row], components=components)
    if ownership == "disagree":
        assert not records and "component_scope_disagreement" in gaps[0]
    elif ownership in {"unowned", "ambiguous"}:
        assert len(records) == 1 and records[0]["subject"]["component_id"] is None
        assert records[0]["subject"]["component_ownership"] == ownership
        assert "component_ownership" in gaps[0]
    elif ownership == "shared":
        assert not gaps and {item["subject"]["component_id"] for item in records} == {
            "component:app", "component:other"}
        assert len({item["subject"]["logical_id"] for item in records}) == 1
    else:
        assert not gaps and records[0]["subject"]["component_id"] == "component:other"


def test_swift_policy_and_managed_memory_are_not_promoted():
    row = fact(language="swift", path="app.swift")
    assert "unsupported_language" in collect([row])[1][0]
    assert collect([row], enable_swift=True)[0][0]["tag"] == "func:data:sql-query"
    assert "unmapped_class" in collect([fact("memory_write", language="java")])[1][0]


def test_partial_producer_coverage_does_not_hide_eligible_scoped_operations():
    row = payload_change(fact(), gaps=["framework models are incomplete"])
    indexes = CannedIndexes(groups=[({**shard(), "gaps": ["another family was truncated"]}, [row])])
    records, gaps = collect(indexes=indexes)
    assert len(records) == 1 and records[0]["basis"] == "invoked"
    assert any("producer_coverage" in gap and "truncated" in gap for gap in gaps)
    assert any("producer_fact_gap" in gap and "incomplete" in gap for gap in gaps)
