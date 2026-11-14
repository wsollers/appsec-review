from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from appsec_review.owasp_workbench import evidence
from appsec_review.review.scope import Component


SQL = "def lookup(cursor):\n    return cursor.execute('SELECT 1')\n"


def select(boundary, settings):
    return evidence.component_evidence(boundary.resolver, "api", boundary.files, settings)


def test_accepted_inputs_wires_complete_selection_and_verifies_scope(accepted, settings, monkeypatch):
    boundary = accepted({"app.py": "# before\n" * 200 + SQL, "other.js": "// unknown\n"})
    verified = []
    boundary.scope.verify = lambda: verified.append(True)
    monkeypatch.setattr(evidence, "accept_manifest", lambda *args, **kwargs: boundary.scope)
    monkeypatch.setattr(evidence, "EvidenceResolver", lambda *args, **kwargs: boundary.resolver)
    result = evidence.accepted_inputs(boundary.resolver.core, settings,
                                     manifest_path=boundary.scope.manifest_path)
    assert verified == [True] and result["input_mode"] == "accepted_indexes"
    [item] = result["evidence"]
    assert item["reference"]["locator"]["lines"] == [201, 202]
    assert result["components"][0]["paths"] == ["app.py", "other.js"]
    assert any("unsupported source" in gap for gap in result["components"][0]["limitations"])
    fingerprint = result["components"][0]["evidence_fingerprint"]
    changed = evidence.accepted_inputs(boundary.resolver.core,
        replace(settings, max_discovery_bytes=settings.max_discovery_bytes - 1),
        manifest_path=boundary.scope.manifest_path)
    assert fingerprint != changed["components"][0]["evidence_fingerprint"]


def test_changed_unsupported_source_identity_invalidates_component_coverage(accepted, settings, monkeypatch):
    boundary = accepted({"app.js": "// unknown\n"})
    monkeypatch.setattr(evidence, "accept_manifest", lambda *args, **kwargs: boundary.scope)
    monkeypatch.setattr(evidence, "EvidenceResolver", lambda *args, **kwargs: boundary.resolver)
    before = evidence.accepted_inputs(boundary.resolver.core, settings, manifest_path=boundary.scope.manifest_path)
    boundary.entities[boundary.files[0].identity]["location"]["file_sha256"] = "f" * 64
    after = evidence.accepted_inputs(boundary.resolver.core, settings, manifest_path=boundary.scope.manifest_path)
    assert before["components"][0]["evidence_fingerprint"] != after["components"][0]["evidence_fingerprint"]
    assert not boundary.reads


@pytest.mark.parametrize("damage", ["hash", "line"])
def test_corrupt_index_source_binding_is_integrity_failure(accepted, settings, damage):
    boundary = accepted({"app.py": SQL}, hints=(("app.py", 1, 2),))
    hint = next(row for row in boundary.rows if row["kind"] == "symbol")
    hint["location"]["file_sha256" if damage == "hash" else "end_line"] = "f" * 64 if damage == "hash" else 99
    with pytest.raises(ValueError, match="index location disagrees"):
        select(boundary, settings)


@pytest.mark.parametrize("damage", ["ambiguous", "invalid_line", "conflicting_owner"])
def test_unresolved_index_location_is_named_gap_with_original_source_fallback(accepted, settings, damage):
    boundary = accepted({"app.py": SQL}, hints=(("app.py", 1, 2),))
    hint = next(row for row in boundary.rows if row["kind"] == "symbol")
    if damage == "ambiguous":
        hint["location"]["ambiguous"] = True
    elif damage == "invalid_line":
        hint["location"]["start_line"] = 0
    else:
        hint["payload"]["component_id"] = "foreign"
    [item], gaps = select(boundary, settings)
    assert item["source_subject"]["complete"]
    assert any("1 location omitted" in gap or "1 record omitted" in gap for gap in gaps)


def test_index_scan_bound_is_explicit_and_does_not_remove_fallback(accepted, settings):
    boundary = accepted({"app.py": SQL}, hints=tuple(("app.py", 1, 2) for _ in range(12)))
    [item], gaps = select(boundary, replace(settings, max_discovery_files=1))
    assert item["source_subject"]["complete"]
    assert any("index scan cap reached" in gap and "count unknown" in gap for gap in gaps)


def test_ambiguous_source_ownership_cannot_create_subject(accepted, settings):
    boundary = accepted({"app.py": SQL})
    boundary.scope.components += (Component("other", ".", "other-component"),)
    values, gaps = select(boundary, settings)
    assert not values and not boundary.reads
    assert any("ambiguous source ownership" in gap for gap in gaps)


def test_unresolved_source_owner_cannot_create_subject(accepted, settings):
    boundary = accepted({"app.py": SQL})
    boundary.scope.components = (Component("other", ".", "other-component"),)
    values, gaps = select(boundary, settings)
    assert not values and any("unresolved source ownership" in gap for gap in gaps)


@pytest.mark.parametrize("damage", ["missing_location", "different_path", "invalid_span"])
def test_corrupt_source_inventory_fails_closed_even_without_recognized_sites(accepted, settings, damage):
    boundary = accepted({"app.py": "x = 1\n"})
    entity = boundary.entities[boundary.files[0].identity]
    if damage == "missing_location":
        entity["location"] = None
    elif damage == "different_path":
        entity["location"]["path"] = "foreign.py"
    else:
        entity["location"]["end_byte"] = 9999
    with pytest.raises(ValueError, match="source inventory disagrees|outside verified"):
        select(boundary, settings)


def test_extra_accepted_facts_preserve_caps_and_unusable_fact_gaps(accepted, settings):
    boundary = accepted({"app.py": SQL})
    for identity, payload in (("fact-a", {"result": {"binding": "unknown"}}), ("fact-b", {}),
                              ("fact-c", {"result": "not requested"})):
        row = {"identity": identity, "kind": "tool_observation", "index": "analysis",
               "shard_id": "default", "location": None, "payload": {"component_id": "api", **payload}}
        boundary.rows.append(row)
        boundary.entities[identity] = row
    values, gaps = select(boundary, replace(settings, max_evidence_per_component=3))
    assert len(values) == 2 and values[1]["category"] == "static_fact"
    assert any("no meaningful structured locator" in gap for gap in gaps)
    assert any("1 accepted non-subject records omitted" in gap for gap in gaps)


def test_model_conclusion_index_locations_never_prioritize_source(accepted, settings):
    boundary = accepted({"a.py": SQL, "z.py": SQL}, hints=(("z.py", 1, 2),))
    hint = next(row for row in boundary.rows if row["kind"] == "symbol")
    hint["payload"]["producer"] = "model"
    [item], gaps = select(boundary, replace(settings, max_evidence_per_component=1))
    assert item["reference"]["locator"]["path"] == "a.py"
    assert any("1 complete recognized subjects omitted" in gap for gap in gaps)


def test_duplicate_inventory_identity_does_not_consume_budget_twice(accepted, settings):
    boundary = accepted({"app.py": SQL})
    boundary.files.append(boundary.files[0])
    values, gaps = select(boundary, replace(settings, max_discovery_bytes=len(SQL.encode())))
    assert len(values) == 1 and not gaps


def test_original_source_identity_is_retained_when_index_hints_are_graph_context(accepted, settings):
    boundary = accepted({"app.py": SQL}, hints=(("app.py", 1, 2),))
    hint = next(row for row in boundary.rows if row["kind"] == "symbol")
    hint["index"], hint["kind"] = "graph", "tool_observation"
    shard = {"name": "graph", "shard_id": "default", "sha256": "4" * 64,
             "producer": {"job": "job_code_graph_index"}}
    boundary.resolver.shards["graph", "default"] = shard
    values, _ = select(boundary, settings)
    assert values[0]["category"] == "source"
    assert values[0]["reference"]["source_identity"] == boundary.files[0].identity
    assert values[0]["reference"]["publication"]["index"] == "source"


def test_subject_identity_resolves_again_after_cache_population(accepted, settings):
    boundary = accepted({"app.py": SQL})
    [item], _ = select(boundary, settings)
    boundary.data["app.py"] = SQL.replace("SELECT 1", "SELECT 2").encode()
    with pytest.raises(ValueError, match="changed after indexing"):
        boundary.resolver.resolve(deepcopy(item["reference"]), component_id="api")


def test_other_component_and_unlocated_graph_context_do_not_supply_subjects(accepted, settings):
    boundary = accepted({"app.py": SQL})
    boundary.scope.components += (Component("other", "other", "other-component"),)
    boundary.rows.append({"identity": "other-fact", "kind": "tool_observation", "index": "analysis",
                          "shard_id": "default", "location": None, "payload": {"component_id": "other"}})
    shard = {"name": "graph", "shard_id": "default", "sha256": "4" * 64,
             "producer": {"job": "job_code_graph_index"}}
    boundary.resolver.shards["graph", "default"] = shard
    boundary.rows.append({"identity": "graph-fact", "kind": "tool_observation", "index": "graph",
                          "shard_id": "default", "location": None, "payload": {"component_id": "api"}})
    values, gaps = select(boundary, settings)
    assert len(values) == 1 and not gaps
    assert values[0]["reference"]["source_identity"] == boundary.files[0].identity


def test_located_scanner_record_cannot_bypass_source_discovery_budget(accepted, settings):
    boundary = accepted({"app.py": SQL})
    row = deepcopy(boundary.rows[0])
    row.update(identity="scanner", kind="tool_observation", index="analysis")
    boundary.rows.append(row)
    values, gaps = select(boundary, replace(settings, max_discovery_bytes=1))
    assert not values
    assert any("1 located non-subject record omitted" in gap for gap in gaps)
    assert boundary.reads == [("app.py", 1)]
