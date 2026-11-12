"""The structure lane (T-107): processes, libraries and links from accepted build evidence.

Payloads use the keys the producers publish (see the module docstring of the lane).
"""
from __future__ import annotations

import random
from typing import Any

from appsec_review.interchange import GapCode
from appsec_review.threat_model.contract import (
    Basis, EvidenceRecord, Fact, FactKind, InputState, LaneResult, Limits, canonical,
)
from appsec_review.threat_model.lanes.structure import structure
from appsec_review.threat_model.view import Page
from tests.threat_model_support import FakeEvidenceView, record

CATALOG, INDEXING = "job_target_catalog", "job_artifact_indexing"
BUILD, CPP = "job_language_build", "job_cpp_compiled_analysis"
UNIT = "native-cmake-0001"


def _point(name: str, kind: str, *sources: str) -> dict[str, Any]:
    return {"name": name, "kind": kind, "evidence": "CMakeLists.txt:3", "sources": sorted(sources),
            "include_dirs": []}


def _unit(*points: dict[str, Any], unit: str = UNIT, root: str = ".") -> EvidenceRecord:
    return record(CATALOG, "build_units", "build_action", f"ent:unit:{unit}", {
        "build_unit_id": unit, "root": root, "family": "native", "build_system": "cmake",
        "markers": [{"path": "CMakeLists.txt", "sha256": "d" * 64, "size_bytes": 120}],
        "provenance": "deterministic-marker", "build_points": list(points)}, name="cmake")


def _component(component_id: str, root: str) -> EvidenceRecord:
    return record(CATALOG, "components", "component", f"ent:{component_id}", {
        "component_id": component_id, "root": root, "manifest": None, "manifest_sha256": None})


def _artifact(path: str, kind: str = "executable", *, unit: str = UNIT, producer: str = INDEXING,
              output_kind: str = "artifact_catalog") -> EvidenceRecord:
    family = "library" if "library" in kind else "executable"
    return record(producer, output_kind, family, f"ent:{producer}:{unit}:{path}", {
        "workspace_path": path, "sha256": "e" * 64, "size_bytes": 4096, "kind": kind, "build_unit_id": unit,
        "mapping": "exact-workspace-path", "scope_role": "deliverable", "delivery_status": "delivered",
        "artifact_origin": "build-output"}, name=path.rsplit("/", 1)[-1])


def _link(source: EvidenceRecord, target: EvidenceRecord) -> EvidenceRecord:
    return record(INDEXING, "artifact_relationships", "LINKS_INTO", f"rel:{source.entity_id}>{target.entity_id}", {
        "source_id": source.entity_id, "target_id": target.entity_id, "build_unit_id": UNIT,
        "observation_count": 1,
        "observations": [{"invocation_index": 0, "input_index": 1, "origin": "trace", "tool": "ld"}]})


def _facts(result: LaneResult, kind: FactKind) -> list[Fact]:
    return [fact for fact in result.facts if fact.kind is kind]


def _gaps(result: LaneResult, code: GapCode) -> list[str]:
    return [gap["scope_id"] for gap in result.gaps if gap["code"] == code.value]


class ShuffledView(FakeEvidenceView):
    """Returns each page in a seeded arbitrary order instead of entity-id order."""

    def __init__(self, seed: int) -> None:
        super().__init__()
        self._random = random.Random(seed)

    def entities(self, producer: str, output_kind: str, kind: str, *, limit: int) -> Page:
        page = super().entities(producer, output_kind, kind, limit=limit)
        records = list(page.records)
        self._random.shuffle(records)
        return Page(tuple(records), page.truncated)


def test_built_executable_becomes_a_process_citing_the_artifact() -> None:
    artifact = _artifact("build/bin/server.exe")
    result = structure(FakeEvidenceView().add(artifact), Limits())
    (process,) = result.facts
    assert (process.kind, process.name, process.basis) == (FactKind.PROCESS, "server", Basis.DECLARED)
    assert dict(process.native_identity) == {"build_unit_id": UNIT, "name": "server"}
    assert [(ref.entity_id, ref.rule) for ref in process.evidence] == [(artifact.entity_id, "structure.built_artifact")]
    assert dict(process.attributes) == {
        "build_unit_id": UNIT, "artifact_path": "build/bin/server.exe", "component_ids": (), "source_paths": (),
        "source_roots": (), "built": True}
    read = {(row.producer, row.output_kind): row for row in result.ledger}
    assert read[(INDEXING, "artifact_catalog")].records_read == 1
    assert read[(INDEXING, "artifact_catalog")].state is InputState.READ


def test_declared_executable_is_a_process_with_declared_basis_when_nothing_was_built() -> None:
    view = FakeEvidenceView().add(
        _unit(_point("server", "executable", "services/net/src/main.c", "services/net/src/io.c"),
              _point("net_check", "test_program", "services/net/tests/check.c"), root="services/net"),
        _component("component:0001", "."), _component("component:0002", "services"),
        _component("component:0003", "services/netx"))
    server, check = sorted(_facts(structure(view, Limits()), FactKind.PROCESS), key=lambda fact: fact.name,
                           reverse=True)
    assert (server.basis, server.evidence[0].basis, server.evidence[0].rule) == (
        Basis.DECLARED, Basis.DECLARED, "structure.declared_build_point")
    assert dict(server.attributes) == {
        "build_unit_id": UNIT, "artifact_path": None, "component_ids": ("component:0002",),
        "source_paths": ("services/net/src/io.c", "services/net/src/main.c"),
        "source_roots": ("services/net/",), "built": False}
    assert check.attributes["test_only"] is True and check.attributes["built"] is False


def test_declared_and_built_executable_of_one_unit_are_one_process_with_both_citations() -> None:
    unit, artifact = _unit(_point("server", "executable", "src/main.c")), _artifact("build/server")
    other = _artifact("build/server", unit="native-cmake-0002")
    result = structure(FakeEvidenceView().add(unit, artifact, other), Limits())
    first, second = _facts(result, FactKind.PROCESS)
    assert dict(first.native_identity) == {"build_unit_id": UNIT, "name": "server"}
    assert {ref.entity_id: ref.rule for ref in first.evidence} == {
        unit.entity_id: "structure.declared_build_point", artifact.entity_id: "structure.built_artifact"}
    assert (first.attributes["built"], first.attributes["artifact_path"], first.attributes["source_roots"]) == (
        True, "build/server", ("",))
    assert first.attributes["source_paths"] == ("src/main.c",)
    declared_only = structure(FakeEvidenceView().add(unit), Limits()).facts[0]
    assert declared_only.native_identity == first.native_identity, "identity does not depend on what was built"
    assert second.native_identity["build_unit_id"] == "native-cmake-0002" and len(second.evidence) == 1


def test_library_folds_into_the_processes_it_links_into() -> None:
    server, worker = _artifact("build/server"), _artifact("build/worker")
    core, util = _artifact("build/libcore.a", "static-library"), _artifact("build/libutil.so.1", "shared-library")
    obj = record(INDEXING, "artifact_catalog", "object_file", "ent:obj", {"workspace_path": "build/main.o"})
    view = FakeEvidenceView().add(
        _unit(_point("core", "static_library", "src/core.c")), server, worker, core, util, obj,
        _link(core, server), _link(core, worker), _link(util, core), _link(obj, server), _link(server, worker),
        _link(core, core))
    result = structure(view, Limits())
    libraries = _facts(result, FactKind.LIBRARY)
    assert [fact.name for fact in libraries] == ["core", "util"]
    assert (libraries[0].attributes["built"], libraries[0].attributes["source_paths"], len(libraries[0].evidence)) == (
        True, ("src/core.c",), 2)
    links = {(fact.attributes["input"]["name"], fact.attributes["output"]["name"]): fact
             for fact in _facts(result, FactKind.LINK)}
    assert sorted(links) == [("core", "server"), ("core", "worker"), ("util", "core")]
    link = links[("core", "server")]
    assert dict(link.attributes["input"]) == {"build_unit_id": UNIT, "name": "core"}
    assert dict(link.attributes["output"]) == {"build_unit_id": UNIT, "name": "server"}
    assert link.attributes["input"] == libraries[0].native_identity
    assert [(ref.entity_kind, ref.rule) for ref in link.evidence] == [("LINKS_INTO", "structure.link_relation")]
    assert link.evidence[0].entity_id == _link(core, server).entity_id


def test_library_with_no_link_evidence_yields_no_link() -> None:
    view = FakeEvidenceView().add(_artifact("build/server"), _artifact("build/libcore.a", "static-library"))
    view.set_status(INDEXING, "artifact_relationships", InputState.READ)
    result = structure(view, Limits())
    assert [(fact.kind, fact.name) for fact in result.facts] == [(FactKind.LIBRARY, "core"), (FactKind.PROCESS, "server")]
    assert result.unknowns == () and _gaps(result, GapCode.EMPTY_RESULT) == []


def test_absent_build_inputs_are_named_gaps_and_declared_units_still_yield_processes() -> None:
    view = FakeEvidenceView().add(_unit(_point("server", "bin", "src/main.rs")), _component("component:0001", "."))
    view.set_status(BUILD, "build_actions", InputState.DISABLED)
    view.set_status(CPP, "cpp_build_graph", InputState.PARTIAL, coverage="partial", upstream_gap_count=2)
    result = structure(view, Limits())
    (process,) = result.facts
    assert (process.kind, process.attributes["built"], process.attributes["component_ids"]) == (
        FactKind.PROCESS, False, ("component:0001",))
    assert sorted(_gaps(result, GapCode.INPUT_UNAVAILABLE)) == [INDEXING, INDEXING, BUILD]
    assert _gaps(result, GapCode.PRODUCER_REPORTED_GAP) == [f"{CPP}/cpp_build_graph"]
    assert all(gap["unit_id"] == "facts.structure" for gap in result.gaps) and len(result.gaps) == 4
    states = {(row.producer, row.output_kind): (row.state, row.records_read) for row in result.ledger}
    assert states == {
        (CATALOG, "build_units"): (InputState.READ, 1), (CATALOG, "components"): (InputState.READ, 1),
        (INDEXING, "artifact_catalog"): (InputState.ABSENT, 0),
        (INDEXING, "artifact_relationships"): (InputState.ABSENT, 0),
        (BUILD, "build_actions"): (InputState.DISABLED, 0), (CPP, "cpp_build_graph"): (InputState.PARTIAL, 0)}
    assert [(row.producer, row.output_kind) for row in result.ledger] == sorted(states)
    assert not any(query[1] in {INDEXING, BUILD} for query in view.queries), "an unreadable input is never queried"


def test_process_limit_reached_is_a_truncated_gap() -> None:
    names = ["delta", "alpha", "charlie", "bravo"]
    core = _artifact("build/libcore.a", "static-library")
    artifacts = {name: _artifact(f"build/{name}") for name in names}
    view = FakeEvidenceView().add(core, *artifacts.values(), *(_link(core, item) for item in artifacts.values()))
    result = structure(view, Limits(max_processes=2), unit_id="facts.custom")
    assert [fact.name for fact in _facts(result, FactKind.PROCESS)] == ["alpha", "bravo"]
    assert [fact.attributes["output"]["name"] for fact in _facts(result, FactKind.LINK)] == ["alpha", "bravo"]
    assert len(_facts(result, FactKind.LIBRARY)) == 1, "the bound is on processes only"
    assert _gaps(result, GapCode.TRUNCATED) == ["structure.max_processes"]
    assert result.gaps[-1]["unit_id"] == "facts.custom"
    assert _gaps(structure(view, Limits(max_processes=4)), GapCode.TRUNCATED) == []


def test_query_bound_reached_is_a_truncated_gap_naming_the_query() -> None:
    view = FakeEvidenceView().add(_artifact("build/server"), _artifact("build/worker"),
                                  _artifact("build/libcore.a", "static-library"))
    result = structure(view, Limits(max_query_rows=1))
    assert _gaps(result, GapCode.TRUNCATED) == ["structure.artifact_catalog.executable"]
    assert [fact.name for fact in _facts(result, FactKind.PROCESS)] == ["server"]
    assert view.queries and all(query[-1] == 1 for query in view.queries)
    assert {(row.producer, row.output_kind): row.records_read for row in result.ledger}[
        (INDEXING, "artifact_catalog")] == 2


def _populate(view: FakeEvidenceView) -> FakeEvidenceView:
    server, worker = _artifact("build/server"), _artifact("build/worker", unit="native-cmake-0002")
    core = _artifact("build/libcore.a", "static-library")
    again = _artifact("out/server", producer=BUILD, output_kind="build_actions")
    return view.add(
        _unit(_point("server", "executable", "src/main.c", "src/io.c"), _point("core", "library", "src/core.c")),
        _unit(_point("worker", "executable", "worker/main.c"), unit="native-cmake-0002", root="worker"),
        _component("component:0001", "."), _component("component:0002", "worker"),
        server, worker, core, again, _link(core, server), _link(core, worker),
        *_compiled_graph("build/server", "src/gen.c", "src/main.c"))


def _compiled_graph(output: str, *sources: str) -> list[EvidenceRecord]:
    def cpp(kind: str, entity_id: str, payload: dict[str, Any]) -> EvidenceRecord:
        return record(CPP, "cpp_build_graph", kind, entity_id, {**payload, "project_id": "cpp:.", "shard_id": "cpp-x"})

    executable = cpp("executable", "ent:cpp:exe", {"kind": "executable", "path": output, "sha256": "f" * 64})
    records = [executable]
    for index, source in enumerate(sources):
        unit = cpp("compile_unit", f"ent:cpp:tu:{index}", {
            "compile_unit_id": f"tu{index}", "target_path": source, "output_path": f"build/{index}.o",
            "arguments": ["clang", "-c", source], "command_sha256": "9" * 64})
        obj = cpp("object_file", f"ent:cpp:obj:{index}", {"kind": "object", "path": f"build/{index}.o"})
        records += [unit, obj,
                    cpp("COMPILES_TO", f"rel:c:{index}", {"source_id": unit.entity_id, "target_id": obj.entity_id,
                                                          "mapping": "compile-database-output"}),
                    cpp("LINKS_INTO", f"rel:l:{index}", {"source_id": obj.entity_id, "target_id": executable.entity_id,
                                                         "mapping": "captured-link-command"})]
    return records


def test_result_is_independent_of_record_order() -> None:
    expected = structure(_populate(FakeEvidenceView()), Limits(max_evidence_refs_per_element=2))
    assert len(expected.facts) == 5 and expected.gaps == ()
    for seed in range(5):
        shuffled = structure(_populate(ShuffledView(seed)), Limits(max_evidence_refs_per_element=2))
        assert canonical(shuffled) == canonical(expected)
    assert [(fact.kind.value, fact.name) for fact in expected.facts] == [
        ("library", "core"), ("link", "core -> server"), ("link", "core -> worker"), ("process", "server"),
        ("process", "worker")]
    assert all(len(fact.evidence) <= 2 for fact in expected.facts)


def test_compiled_graph_artifact_joins_the_named_process_and_supplies_sources() -> None:
    graph = _compiled_graph("build/server", "src/gen.c", "../outside.c")
    joined = structure(FakeEvidenceView().add(_unit(_point("server", "executable", "src/main.c")), *graph), Limits())
    (process,) = joined.facts
    assert dict(process.native_identity) == {"build_unit_id": UNIT, "name": "server"}
    assert (process.attributes["built"], process.attributes["source_paths"]) == (True, ("src/gen.c", "src/main.c"))
    assert {ref.rule for ref in process.evidence} == {"structure.declared_build_point", "structure.built_artifact"}
    (alone,) = structure(FakeEvidenceView().add(*graph), Limits()).facts
    assert dict(alone.native_identity) == {"project_id": "cpp:.", "name": "server"}
    assert (alone.attributes["build_unit_id"], alone.attributes["source_roots"]) == (None, ())


def test_nothing_established_is_an_empty_result_gap() -> None:
    intake = record(INDEXING, "artifact_catalog", "executable", "ent:intake", {
        "workspace_path": "vendor/tool.exe", "kind": "executable", "artifact_origin": "target-intake",
        "target_relative_path": "vendor/tool.exe", "scope_role": "unknown", "delivery_status": "unknown"})
    view = FakeEvidenceView().add(
        _unit(_point("all", "phony_or_aggregate"), _point("objs", "object_library", "src/a.c"),
              _point("", "executable"), {"kind": "executable"}), intake)
    result = structure(view, Limits())
    assert result.facts == () and _gaps(result, GapCode.EMPTY_RESULT) == ["structure"]
    assert result.gaps[-1]["code"] == GapCode.EMPTY_RESULT.value
    nothing_read = structure(FakeEvidenceView(), Limits())
    assert nothing_read.facts == () and _gaps(nothing_read, GapCode.EMPTY_RESULT) == []
    assert len(_gaps(nothing_read, GapCode.INPUT_UNAVAILABLE)) == 6
