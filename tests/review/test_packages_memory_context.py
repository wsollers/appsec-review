"""Schema v5 finding-lead memory and caller context (svf-alias-producer.md section 7)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from appsec_review.graph.contract import Family
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    index_fingerprint, write_manifest,
)
from appsec_review.review.memory_context import SVF_PRODUCER, is_c_family
from appsec_review.review.packages import PACKAGE_SCHEMA, PackageSettings, assemble_packages
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.inference_review.builder import SNAPSHOT, FixtureRun, build_accepted_index_set
from tests.review.test_graph_admissibility import graph_entity
from tests.review.test_packages_graph_context import PARSE, _location, attach_graph

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text(encoding="utf-8"))
IO = "native/src/io.c"
MEMORY_ROLES = {"points_to", "indirect_call", "memory_object"}


def _publish(fixture: FixtureRun, shards: list[tuple[str, str, dict[str, Any], list[EntityRecord],
                                                     list[RelationRecord], tuple[str, str, str | None]]]) -> None:
    """Append shards to the fixture's accepted manifest and re-bind the accepted pointer."""
    run_root = fixture.run_root
    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    identities = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}) for raw in manifest["indexes"]]
    for name, shard_id, producer, entities, relations, coverage in shards:
        fingerprint = index_fingerprint(name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id}],
                                        tool_identity=producer, parser_identity="fixture/1",
                                        normalizer_identity="fixture/1", mapping_identity="fixture/1")
        path = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(*coverage)
        identities.append(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                                        path.relative_to(run_root).as_posix(), producer,
                                        (coverage[2],) if coverage[2] else (), shard_id))
    write_manifest(manifest_path, run_id=fixture.run_id, target_snapshot=SNAPSHOT, target_root=fixture.target,
                   indexes=identities, upstream_manifests=manifest.get("upstream_manifests", ()))
    pointer_path = run_root / "data" / "indices" / "accepted.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff_path = run_root / pointer["handoff_path"]
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    sha = file_sha256(manifest_path)
    for artifact in handoff["artifacts"]:
        if artifact["path"] == pointer["manifest_path"]:
            artifact["sha256"] = sha
    atomic_json(handoff_path, handoff)
    atomic_json(pointer_path, {**pointer, "manifest_sha256": sha, "handoff_sha256": file_sha256(handoff_path)})


def _svf_record(kind: EntityKind, key: str, payload: dict[str, Any], location) -> EntityRecord:
    identity = LogicalIdentity.derive(kind, SNAPSHOT, {"fixture": key})
    base = {"schema": "appsec-review/svf-alias-record/1", "producer": "svf", "tool_version": "3.3.0",
            "scope_id": "cpp-scope-native", "module_id": "m-native", "module_label": "build/native",
            "module_kind": "link", "module_closed_world": True, "open_world_reasons": [], "complete": True}
    return EntityRecord(identity, key, key, key, {**base, **payload}, location)


def svf_shard(fixture: FixtureRun, *, open_world: bool = False):
    """SVF records at parse.c line 3 (``strcpy(b, s)``): two pointer sites and the stack object ``b``."""
    strcpy = _location(fixture, PARSE, "strcpy(b, s)")
    reasons = ["dynamic_loading"] if open_world else []
    common = {"function": "p", "function_demangled": "p", "module_closed_world": not open_world,
              "open_world_reasons": reasons}
    destination = _svf_record(EntityKind.POINTS_TO_SET, "dst", {
        **common, "role": "call_arg", "operand": 0, "callee": "strcpy", "points_to": ["obj:stack:b"]}, strcpy)
    source = _svf_record(EntityKind.POINTS_TO_SET, "src", {
        **common, "role": "call_arg", "operand": 1, "callee": "strcpy", "points_to": ["obj:global:input"]}, strcpy)
    buffer = _svf_record(EntityKind.MEMORY_OBJECT, "obj-b", {
        "schema": "appsec-review/svf-memory-object/1", "object_key": "obj:stack:b", "kind": "stack", "name": "b",
        "allocator": None, "accessors": [{"site": destination.identity.value, "class": "pass"}],
        "accessor_counts": {"free": 0, "write": 0, "read": 0, "compare": 0, "pass": 1}, "accessor_total": 1,
        "truncated": False, **common}, _location(fixture, PARSE, "char b[8]"))
    relations = [RelationRecord(RelationKind.REFERENCES, destination.identity.value, buffer.identity.value, True, 1.0,
                                None, {"rule": "svf-memory-object/1", "class": "pass"})]
    return ("analysis", "svf-cpp-scope-native", {"job": "job_svf_alias_analysis", "scope_id": "cpp-scope-native"},
            [destination, source, buffer], relations, ("svf:cpp:native:build/native", "complete", None)), {
        "dst": destination.identity.value, "src": source.identity.value, "obj": buffer.identity.value}


def call_shard(fixture: FixtureRun):
    """call_site facts: r() calls p() (depth 1) and q() calls r() (depth 2); both callees lack symbols."""
    def call(caller: str, callee: str, path: str, needle: str) -> EntityRecord:
        location = _location(fixture, path, needle)
        return graph_entity(Family.CALL_SITE, {"caller_symbol": f"fixture:{caller}", "path": path,
                                               "start_byte": location.start_byte,
                                               "end_byte": location.end_byte, "callee_name": callee},
                            {"caller": {"symbol": None, "display": caller},
                             "callee": {"symbol": None, "display": callee, "dispatch": "direct",
                                        "candidate_count": 1}, "argument_count": 0, "in_loop": False},
                            location, snapshot=SNAPSHOT)
    depth_one = call("r", "p", IO, "return 0;")
    depth_two = call("q", "r", PARSE, "n * 4")
    unrelated = call("q", "strlen", PARSE, "return n")
    return ("graph", "cpp-native-call_site", {"job": "job_code_graph_index", "family": "call_site",
                                              "build_unit_id": "native-main"},
            [depth_one, depth_two, unrelated], [], ("graph:native:call_site", "complete", None)), {
        "depth_one": depth_one.identity.value, "depth_two": depth_two.identity.value,
        "unrelated": unrelated.identity.value}


@pytest.fixture(scope="module")
def memory_fixture(tmp_path_factory):
    fixture = build_accepted_index_set(tmp_path_factory.mktemp("mem"))
    attach_graph(fixture)
    svf, svf_ids = svf_shard(fixture)
    calls, call_ids = call_shard(fixture)
    _publish(fixture, [svf, calls])
    return fixture, {**svf_ids, **call_ids}


def _lead(assembly, fixture: FixtureRun, key: str) -> dict:
    [document] = [item.document() for item in assembly.packages
                  if item.kind == "finding_lead" and item.lead_ids == (fixture.ids[key],)]
    return document


def _roles(document: dict, roles: set[str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for entry in document["context"]:
        if entry["role"] in roles:
            found.setdefault(entry["role"], set()).add(entry["id"])
    return found


def _gaps(document: dict, producer: str) -> list[dict]:
    return [gap for gap in document["coverage_gaps"] if gap["producer"] == producer]


def test_any_scanners_cpp_lead_gets_the_svf_records_at_its_line_and_their_objects(memory_fixture) -> None:
    fixture, ids = memory_fixture
    assembly = assemble_packages(accept_manifest(fixture.run_root))
    document = _lead(assembly, fixture, "sast_critical")   # a Semgrep strcpy lead at parse.c:3
    assert document["schema"] == PACKAGE_SCHEMA == "appsec-review/review-package/6"
    assert _roles(document, MEMORY_ROLES) == {"points_to": {ids["dst"], ids["src"]}, "memory_object": {ids["obj"]}}
    assert _gaps(document, SVF_PRODUCER) == []
    assert {ids["dst"], ids["src"], ids["obj"]} <= set(document["retrieval"]["entity_ids"])
    jsonschema.Draft202012Validator(SCHEMA).validate(document)


def test_callers_follow_the_enclosing_function_to_the_configured_depth(memory_fixture) -> None:
    fixture, ids = memory_fixture
    deep = assemble_packages(accept_manifest(fixture.run_root))
    callers = _roles(_lead(deep, fixture, "sast_critical"), {"caller"})["caller"]
    assert callers == {ids["depth_one"], ids["depth_two"]}
    gaps = _gaps(_lead(deep, fixture, "sast_critical"), "code_graph_callers")
    assert any(gap["state"] == "ambiguous" and "unqualified function name" in gap["reason"] for gap in gaps)
    shallow = assemble_packages(accept_manifest(fixture.run_root), PackageSettings(caller_depth=1))
    assert _roles(_lead(shallow, fixture, "sast_critical"), {"caller"})["caller"] == {ids["depth_one"]}
    capped = assemble_packages(accept_manifest(fixture.run_root), PackageSettings(max_callers=1))
    document = _lead(capped, fixture, "sast_critical")
    assert _roles(document, {"caller"})["caller"] == {ids["depth_one"]}
    assert any(gap["state"] == "truncated" and "max_callers=1" in gap["reason"]
               for gap in _gaps(document, "code_graph_callers"))


def test_a_line_without_pointer_sites_and_non_c_leads_are_handled_honestly(memory_fixture) -> None:
    fixture, _ids = memory_fixture
    assembly = assemble_packages(accept_manifest(fixture.run_root))
    codeql = _lead(assembly, fixture, "codeql_high")         # parse.c:5 holds no SVF record
    assert not _roles(codeql, MEMORY_ROLES)
    [gap] = _gaps(codeql, SVF_PRODUCER)
    assert gap["state"] == "unavailable" and "no SVF pointer site or indirect call at native/src/parse.c:5" in gap["reason"]
    python = _lead(assembly, fixture, "sast_high")            # svc/api/handler.py
    assert not _roles(python, MEMORY_ROLES) and _gaps(python, SVF_PRODUCER) == []
    io = _lead(assembly, fixture, "sast_suppressed")           # io.c is in no SVF module
    assert "is in no analyzed SVF module" in _gaps(io, SVF_PRODUCER)[0]["reason"]


def test_memory_context_bound_keeps_objects_first_and_names_the_truncation(memory_fixture) -> None:
    fixture, ids = memory_fixture
    assembly = assemble_packages(accept_manifest(fixture.run_root), PackageSettings(max_memory_context_entries=1))
    document = _lead(assembly, fixture, "sast_critical")
    assert _roles(document, MEMORY_ROLES) == {"memory_object": {ids["obj"]}}
    assert any(gap["state"] == "truncated" and "max_memory_context_entries=1" in gap["reason"]
               for gap in _gaps(document, SVF_PRODUCER))


def test_reassembly_is_byte_identical(memory_fixture) -> None:
    fixture, _ids = memory_fixture
    first = assemble_packages(accept_manifest(fixture.run_root))
    second = assemble_packages(accept_manifest(fixture.run_root))
    assert [item.body for item in first.packages] == [item.body for item in second.packages]


def test_without_svf_shards_a_cpp_lead_names_the_missing_producer(tmp_path_factory) -> None:
    fixture = build_accepted_index_set(tmp_path_factory.mktemp("nosvf"))
    assembly = assemble_packages(accept_manifest(fixture.run_root))
    [gap] = _gaps(_lead(assembly, fixture, "sast_critical"), SVF_PRODUCER)
    assert gap["state"] == "missing" and "opt-in" in gap["reason"]


def test_open_world_records_are_kept_with_a_partial_gap(tmp_path_factory) -> None:
    fixture = build_accepted_index_set(tmp_path_factory.mktemp("openw"))
    svf, ids = svf_shard(fixture, open_world=True)
    _publish(fixture, [svf])
    document = _lead(assemble_packages(accept_manifest(fixture.run_root)), fixture, "sast_critical")
    assert _roles(document, {"points_to"})["points_to"] == {ids["dst"], ids["src"]}
    [gap] = _gaps(document, SVF_PRODUCER)
    assert gap["state"] == "partial" and "dynamic_loading" in gap["reason"] and "never rule out" in gap["reason"]


def test_c_family_detection() -> None:
    assert is_c_family("a/b.cpp") and is_c_family("x.H") and is_c_family("k.c")
    assert not is_c_family("a.py") and not is_c_family(None) and not is_c_family("Makefile")
