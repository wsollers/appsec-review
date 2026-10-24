"""Schema v4 package graph context and per-unit hunt strategy sources (code-graph plan section 7.5)."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import random
from types import SimpleNamespace
from typing import Any, Iterable

import jsonschema
import pytest

from appsec_review.graph.contract import Family
from appsec_review.guidance.routing import hunt_panel
from appsec_review.jobs.job_inference_security_review import job as review_job
from appsec_review.jobs.job_inference_security_review import teams
from appsec_review.retrieval import (
    EntityRecord, IndexBuilder, IndexIdentity, RelationKind as IndexRelation, RelationRecord, SourceLocation,
    index_fingerprint, write_manifest,
)
from appsec_review.review.lead_families import collect_leads
from appsec_review.review.models import Lane
from appsec_review.review.packages import (
    PACKAGE_SCHEMA, GraphContext, PackageSettings, assemble_packages,
)
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.inference_review.builder import SNAPSHOT, FixtureRun, build_accepted_index_set
from tests.review.test_graph_admissibility import graph_entity, results_for

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text(encoding="utf-8"))
PARSE = "native/src/parse.c"
GRAPH_ROLES = {"entry_point", "sink", "path", "guard", "range"}
PERSONAS = {"memory_safety_native": ("func:exec:unmanaged-memory",), "business_logic_abuse": (),
            "generalist": ()}


def _location(fixture: FixtureRun, path: str, needle: str, occurrence: int = 0) -> SourceLocation:
    source = fixture.target / path
    text = source.read_text(encoding="utf-8")
    start = -1
    for _ in range(occurrence + 1):
        start = text.index(needle, start + 1)
    line = text[:start].count("\n") + 1
    column = start - (text.rfind("\n", 0, start) + 1) + 1
    return SourceLocation(SNAPSHOT, path, file_sha256(source), start, start + len(needle), line, line, column,
                          column + len(needle), {}, "codeql-location-exact", 1.0)


def _span(location: SourceLocation) -> dict[str, Any]:
    return {"path": location.path, "start_byte": location.start_byte, "end_byte": location.end_byte}


def graph_facts(fixture: FixtureRun, *, entry_points: bool = True) -> tuple[dict[str, list[EntityRecord]],
                                                                            list[RelationRecord], dict[str, str]]:
    """Graph facts for the native unit, keyed by family; the CodeQL lead correlates one path."""
    ids: dict[str, str] = {}
    by_family: dict[str, list[EntityRecord]] = {family.value: [] for family in Family}

    def add(key: str, entity: EntityRecord) -> None:
        ids[key] = entity.identity.value
        by_family[entity.identity.kind.value].append(entity)

    param_s, param_n = _location(fixture, PARSE, "char *s"), _location(fixture, PARSE, "int n")
    strcpy, multiply = _location(fixture, PARSE, "strcpy(b, s)"), _location(fixture, PARSE, "n * 4")
    if entry_points:
        add("entry_s", graph_entity(Family.ENTRY_POINT, {**_span(param_s), "source_class": "remote"},
                                    results_for(Family.ENTRY_POINT, "remote"), param_s, snapshot=SNAPSHOT))
        add("entry_n", graph_entity(Family.ENTRY_POINT, {**_span(param_n), "source_class": "argv"},
                                    results_for(Family.ENTRY_POINT, "argv"), param_n, snapshot=SNAPSHOT))
    add("sink_strcpy", graph_entity(Family.SINK_SITE, {**_span(strcpy), "sink_class": "memory_write",
                                                       "argument_index": 0},
                                    results_for(Family.SINK_SITE), strcpy, snapshot=SNAPSHOT))
    add("sink_multiply", graph_entity(Family.SINK_SITE, {**_span(multiply), "sink_class": "integer_conversion",
                                                         "argument_index": 0},
                                      {**results_for(Family.SINK_SITE), "sink_class": "integer_conversion"},
                                      multiply, snapshot=SNAPSHOT))
    # More memory-write sinks so a small context bound must choose by class round-robin.
    for number, needle in enumerate(("char b[8]", "b, s", "b[8]")):
        location = _location(fixture, PARSE, needle)
        add(f"sink_extra_{number}", graph_entity(Family.SINK_SITE, {**_span(location), "sink_class": "memory_write",
                                                                     "argument_index": number + 1},
                                                 results_for(Family.SINK_SITE), location, snapshot=SNAPSHOT))
    entry_n = ids.get("entry_n", "asr:entry_point:" + "6" * 64)
    entry_s = ids.get("entry_s", "asr:entry_point:" + "7" * 64)
    add("path_bridged", graph_entity(
        Family.DATAFLOW_PATH, {"source_identity": entry_n, "sink_identity": ids["sink_multiply"],
                               "step_locations_sha256": "1" * 64},
        results_for(Family.DATAFLOW_PATH, "argv", sink=ids["sink_multiply"], entry=entry_n), multiply,
        snapshot=SNAPSHOT))
    add("path_broken", graph_entity(
        Family.DATAFLOW_PATH, {"source_identity": entry_s, "sink_identity": ids["sink_strcpy"],
                               "step_locations_sha256": "2" * 64},
        results_for(Family.DATAFLOW_PATH, "remote", sink=ids["sink_strcpy"], entry=entry_s), strcpy,
        snapshot=SNAPSHOT))
    add("guard_multiply", graph_entity(
        Family.GUARD_FACT, {"sink_identity": ids["sink_multiply"], "condition_path": PARSE,
                            "condition_start_byte": multiply.start_byte, "condition_end_byte": multiply.end_byte},
        results_for(Family.GUARD_FACT, sink=ids["sink_multiply"]), multiply, snapshot=SNAPSHOT))
    add("guard_strcpy", graph_entity(
        Family.GUARD_FACT, {"sink_identity": ids["sink_strcpy"], "condition_path": PARSE,
                            "condition_start_byte": strcpy.start_byte, "condition_end_byte": strcpy.end_byte},
        results_for(Family.GUARD_FACT, sink=ids["sink_strcpy"]), strcpy, snapshot=SNAPSHOT))
    add("range_multiply", graph_entity(
        Family.RANGE_FACT, {"sink_identity": ids["sink_multiply"], "operand_index": 0},
        results_for(Family.RANGE_FACT, sink=ids["sink_multiply"]), multiply, snapshot=SNAPSHOT))
    relations = [
        RelationRecord(IndexRelation.DERIVED_FROM, ids["path_bridged"], fixture.ids["codeql_high"], True, 1.0,
                       payload={"code_flow": 0, "state": "bridged", "matched_steps": 2, "ambiguous_steps": 0,
                                "unmatched_steps": 0}),
        RelationRecord(IndexRelation.DERIVED_FROM, ids["path_broken"], fixture.ids["codeql_high"], False, 0.5,
                       "sink step matches no sink_site", payload={"code_flow": 1, "state": "broken"}),
        RelationRecord(IndexRelation.GUARDS, ids["guard_multiply"], ids["sink_multiply"], True, 1.0),
    ]
    return by_family, relations, ids


def attach_graph(fixture: FixtureRun, *, entry_points: bool = True, reverse: bool = False) -> dict[str, str]:
    """Publish one graph shard per family into the fixture run and re-accept the manifest."""
    run_root = fixture.run_root
    by_family, relations, ids = graph_facts(fixture, entry_points=entry_points)
    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    identities = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}) for raw in manifest["indexes"]]
    for family in ("sink_site", "entry_point", "dataflow_path", "guard_fact", "range_fact"):
        shard_id = f"cpp-native-{family}"
        entities = list(by_family[family])
        rows = [item for item in relations if item.source_id in {entity.identity.value for entity in entities}]
        if reverse:
            entities.reverse()
            rows.reverse()
        fingerprint = index_fingerprint(name="graph", target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id}],
                                        tool_identity={"family": family}, parser_identity="fixture/1",
                                        normalizer_identity="graph-normalize/1", mapping_identity="fixture/1")
        path = run_root / "data" / "indices" / "graph" / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="graph", fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for entity in entities:
            builder.add_entity(entity)
        for relation in rows:
            builder.add_relation(relation)
        unavailable = family == "entry_point" and not entities
        coverage = ((f"graph:native:{family}", "unavailable", "export query timed out") if unavailable
                    else (f"graph:native:{family}", "complete", None))
        builder.add_coverage(*coverage)
        identities.append(IndexIdentity("graph", "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                                        path.relative_to(run_root).as_posix(),
                                        {"job": "job_code_graph_index", "family": family,
                                         "build_unit_id": "native-main"},
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
    return ids


@pytest.fixture(scope="module")
def graph_fixture(tmp_path_factory) -> tuple[FixtureRun, dict[str, str]]:
    fixture = build_accepted_index_set(tmp_path_factory.mktemp("graphpkg"))
    return fixture, attach_graph(fixture)


@pytest.fixture(scope="module")
def graph_assembly(graph_fixture):
    fixture, _ids = graph_fixture
    return assemble_packages(accept_manifest(fixture.run_root))


def _lead(assembly, fixture: FixtureRun, key: str) -> dict:
    [document] = [item.document() for item in assembly.packages
                  if item.kind == "finding_lead" and item.lead_ids == (fixture.ids[key],)]
    return document


def _native_hunt(assembly) -> dict:
    hunts = [item.document() for item in assembly.packages
             if item.kind == "hunt" and item.document()["scope"]["build_unit_id"] == "native-main"]
    assert len(hunts) == 1
    return hunts[0]


def _graph_entries(document: dict) -> list[dict]:
    return [entry for entry in document["context"] if entry["role"] in GRAPH_ROLES]


def test_every_v4_package_validates_and_names_its_graph_families(graph_assembly) -> None:
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for package in graph_assembly.packages:
        document = package.document()
        validator.validate(document)
        assert document["schema"] == PACKAGE_SCHEMA == "appsec-review/review-package/6"
        assert document["retrieval"]["graph_families"] == sorted(set(document["retrieval"]["graph_families"]))
        assert "graph" in document["retrieval"]["indexes"]
    bad = _native_hunt(graph_assembly)
    bad["retrieval"]["graph_families"] = ["aliases"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(bad)
    stale = _native_hunt(graph_assembly)
    stale["context"].append({"id": "asr:sink_site:" + "0" * 64, "kind": "sink_site", "role": "sink_class"})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(stale)


def test_codeql_lead_embeds_its_correlated_path_sink_guards_and_ranges(graph_fixture, graph_assembly) -> None:
    fixture, ids = graph_fixture
    document = _lead(graph_assembly, fixture, "codeql_high")
    found = {(entry["id"], entry["role"], entry["kind"]) for entry in _graph_entries(document)}
    assert found == {
        (ids["path_bridged"], "path", "dataflow_path"), (ids["sink_multiply"], "sink", "sink_site"),
        (ids["entry_n"], "entry_point", "entry_point"), (ids["guard_multiply"], "guard", "guard_fact"),
        (ids["range_multiply"], "range", "range_fact")}
    # A broken correlation is never embedded as if it were the lead's path, nor its sink's guard.
    assert ids["path_broken"] not in json.dumps(document) and ids["guard_strcpy"] not in json.dumps(document)
    assert set(ids[key] for key in ("path_bridged", "guard_multiply")) <= set(document["retrieval"]["entity_ids"])
    assert document["retrieval"]["graph_families"] == ["dataflow_path", "entry_point", "guard_fact", "range_fact",
                                                       "sink_site"]
    graph_gaps = [gap for gap in document["coverage_gaps"] if gap["producer"] == "code_graph"]
    assert [(gap["state"], "call_site, flow_summary" in gap["reason"]) for gap in graph_gaps] == [
        ("unavailable", True)]
    # A source-SAST lead in the same build unit has no correlated path, but package-neighborhood/1 selects the
    # sink, guard and range facts located on its own line (and in its function) by location, not by correlation.
    sast = _lead(graph_assembly, fixture, "sast_critical")
    assert sast["retrieval"]["graph_families"] == document["retrieval"]["graph_families"]
    assert not [entry for entry in _graph_entries(sast) if entry["id"] == ids["path_bridged"]]
    neighborhood = sast["neighborhood"]
    assert neighborhood["rule"] == "appsec-review/package-neighborhood/1"
    assert ids["sink_strcpy"] in {row["ref"] for row in neighborhood["sinks"]}
    assert ids["guard_strcpy"] in {row["ref"] for row in neighborhood["guards"]}
    assert {row["ref"] for row in neighborhood["sinks"]} <= set(sast["retrieval"]["entity_ids"])
    guard = next(row for row in neighborhood["guards"] if row["ref"] == ids["guard_strcpy"])
    assert guard["summary"].startswith("none guard") and "adequate" not in guard["summary"]
    # A lead in a unit with no graph facts gets no family and a named gap.
    python = _lead(graph_assembly, fixture, "sast_high")
    assert python["retrieval"]["graph_families"] == []
    assert any(gap["producer"] == "code_graph" and gap["state"] == "unavailable" for gap in python["coverage_gaps"])


def test_hunt_graph_context_is_bounded_round_robin_by_class(graph_fixture) -> None:
    fixture, ids = graph_fixture
    scope = accept_manifest(fixture.run_root)
    wide = _native_hunt(assemble_packages(scope))
    every = _graph_entries(wide)
    assert {entry["id"] for entry in every} == {ids[key] for key in ids if key.startswith(("sink_", "entry_"))}
    assert all(entry["role"] in {"sink", "entry_point"} for entry in every)
    non_graph = len(wide["context"]) - len(every)
    bound = non_graph + 3
    narrow = _native_hunt(assemble_packages(scope, PackageSettings(max_context_entries=bound)))
    chosen = _graph_entries(narrow)
    assert len(narrow["context"]) == bound and len(chosen) == 3
    # Buckets in (role, class) order: entry_point/argv, entry_point/remote, sink/integer_conversion, ...
    assert {entry["id"] for entry in chosen} == {ids["entry_n"], ids["entry_s"], ids["sink_multiply"]}
    assert narrow["truncation"]["omitted_context"] == len(every) - 3
    truncated = [gap for gap in narrow["coverage_gaps"] if gap["producer"] == "code_graph" and gap["state"] == "truncated"]
    assert len(truncated) == 1 and f"{len(every) - 3} graph context entries" in truncated[0]["reason"]
    again = _native_hunt(assemble_packages(scope, PackageSettings(max_context_entries=bound)))
    assert again == narrow


def test_package_ids_are_stable_under_shuffled_graph_input(graph_fixture, graph_assembly, tmp_path) -> None:
    fixture, _ids = graph_fixture
    scope = accept_manifest(fixture.run_root)
    generator = random.Random(11)

    def shuffled(values: Iterable) -> tuple:
        values = list(values)
        generator.shuffle(values)
        return tuple(values)
    collection = collect_leads(scope)
    scrambled = replace(scope, shards=shuffled(scope.shards))
    again = assemble_packages(scrambled, collection=replace(collection, leads=shuffled(collection.leads)))
    assert [item.package_id for item in again.packages] == [item.package_id for item in graph_assembly.packages]
    assert again.manifest_bytes == graph_assembly.manifest_bytes
    # The same facts inserted in reverse order in another run give the same graph context.
    other = build_accepted_index_set(tmp_path / "reversed")
    attach_graph(other, reverse=True)
    rebuilt = assemble_packages(accept_manifest(other.run_root))
    volatile = {"package_id", "manifest_sha256", "input_fingerprint"}
    left = sorted(json.dumps({key: value for key, value in item.document().items() if key not in volatile},
                             sort_keys=True) for item in rebuilt.packages)
    right = sorted(json.dumps({key: value for key, value in item.document().items() if key not in volatile},
                              sort_keys=True) for item in graph_assembly.packages)
    assert left == right


def test_graph_context_reads_only_accepted_graph_shards(graph_fixture) -> None:
    fixture, ids = graph_fixture
    context = GraphContext(accept_manifest(fixture.run_root))
    assert context.available and len(context.shards) == 5
    assert context.correlated[fixture.ids["codeql_high"]] == {ids["path_bridged"]}
    assert {item.families for item in context.shards} == {frozenset({family}) for family in (
        "sink_site", "entry_point", "dataflow_path", "guard_fact", "range_fact")}


def _route(document: dict, available: tuple[str, ...]) -> dict:
    ctx = SimpleNamespace(source_languages={}, build_unit_languages={}, entity_name=lambda identity: None,
                          covers=PERSONAS, available_sources=available,
                          core=SimpleNamespace(find=lambda **kwargs: {"results": []}),
                          settings=SimpleNamespace(teams=SimpleNamespace(red_per_team=3)))
    work = teams.PackageWork("hunt-" + "1" * 64, Lane.HUNT, "1" * 64, document, (0, "hunt"),
                             "1" * 64, (), None)
    return teams.route(ctx, work)


def test_entry_down_launches_only_when_the_unit_has_an_accepted_entry_point_family(graph_fixture, tmp_path) -> None:
    fixture, _ids = graph_fixture
    hunt = _native_hunt(assemble_packages(accept_manifest(fixture.run_root)))
    families = hunt["retrieval"]["graph_families"]
    sources = review_job.available_sources(hunt["retrieval"]["query_sets"], families)
    assert {"source_sink_facts", "entry_point_catalog"} <= set(sources) and "symbol_links" not in sources
    routing = _route(hunt, review_job.run_sources(hunt["retrieval"]["query_sets"]))
    assert [cell["strategy"] for cell in routing["panel"]][:2] == ["sink_up", "entry_down"]
    assert not any(item["strategy"] in {"sink_up", "entry_down"} for item in routing["strategy_gaps"])

    # The same unit whose entry-point export is unavailable keeps sink_up and falls back for entry_down.
    degraded = build_accepted_index_set(tmp_path / "no-entry")
    attach_graph(degraded, entry_points=False)
    hunt = _native_hunt(assemble_packages(accept_manifest(degraded.run_root)))
    families = hunt["retrieval"]["graph_families"]
    assert "entry_point" not in families and "sink_site" in families
    sources = review_job.available_sources(hunt["retrieval"]["query_sets"], families)
    assert "entry_point_catalog" not in sources and "source_sink_facts" in sources
    panel = hunt_panel(PERSONAS, unit_tags={}, available_sources=sources)
    assert [cell["strategy"] for cell in panel["cells"]][:2] == ["sink_up", "persona_sweep"]
    assert {"gap_class": "coverage_gap", "strategy": "entry_down",
            "reason": "required_source_unavailable:entry_point_catalog"} in panel["gaps"]
    routing = _route(hunt, ())
    assert {"strategy": "entry_down", "reason": "required_source_unavailable:entry_point_catalog",
            "gap_class": "coverage_gap"} in routing["strategy_gaps"]
    unavailable = [gap for gap in hunt["coverage_gaps"] if gap["producer"] == "code_graph"]
    assert any("entry_point" in gap["reason"] and gap["state"] == "unavailable" for gap in unavailable)


def test_without_a_graph_index_packages_name_the_gap_and_unlock_nothing(tmp_path) -> None:
    fixture = build_accepted_index_set(tmp_path)
    assembly = assemble_packages(accept_manifest(fixture.run_root))
    assert any(gap["producer"] == "code_graph" and gap["scope"] == "run" and gap["state"] == "missing"
               for gap in assembly.manifest["gaps"])
    for package in assembly.packages:
        document = package.document()
        assert document["retrieval"]["graph_families"] == [] and not _graph_entries(document)
        assert any(gap["producer"] == "code_graph" and gap["state"] == "missing" for gap in document["coverage_gaps"])
        if package.kind == "hunt":
            assert review_job.available_sources(document["retrieval"]["query_sets"], []) == ()
            routing = _route(document, ())
            assert {item["strategy"] for item in routing["strategy_gaps"]} >= {"sink_up", "entry_down"}
