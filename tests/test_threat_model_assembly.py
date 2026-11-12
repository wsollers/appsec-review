"""DFD assembly (T-107): elements, flows, boundaries, entry points, actors and unknowns from lane facts.

Facts are real contract records and the reference data is the checkout's. The builders here are
stateless and are reused by the threat, document and validation tests.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import random
from typing import Any

from appsec_review.interchange import GapCode
from appsec_review.threat_model.assemble import Assembly, assemble
from appsec_review.threat_model.contract import (
    Basis, BoundaryKind, ElementKind, Fact, FactKind, Interaction, LaneResult, Limits, NameBasis, UnknownKind,
    canonical, cite, element_id,
)
from appsec_review.threat_model.reference import Reference, load_reference
from tests.threat_model_support import record, span

ROOT = Path(__file__).resolve().parents[1]
LIMITS = Limits()


@lru_cache(maxsize=1)
def reference() -> Reference:
    return load_reference(ROOT)  # immutable reference data, read once per worker


def _structure(kind: FactKind, name: str, unit: str | None, built: bool, paths: tuple[str, ...],
               roots: tuple[str, ...], test_only: bool, entity: str | None) -> Fact:
    evidence = cite(record("job_target_catalog", "build_units", "build_action", entity or f"ent:{kind.value}:{unit}:{name}"),
                    Basis.DECLARED, "structure.declared_build_point")
    attributes: dict[str, Any] = {"build_unit_id": unit, "artifact_path": f"bin/{name}" if built else None,
                                  "component_ids": (), "source_paths": paths, "source_roots": roots, "built": built}
    if test_only:
        attributes["test_only"] = True
    return Fact(kind, {"build_unit_id": unit, "name": name}, name, Basis.DECLARED, (evidence,), attributes)


def process(name: str, *, unit: str | None = "unit-a", built: bool = True, paths: tuple[str, ...] = (),
            roots: tuple[str, ...] = ("",), test_only: bool = False, entity: str | None = None) -> Fact:
    return _structure(FactKind.PROCESS, name, unit, built, paths, roots, test_only, entity)


def library(name: str, *, unit: str | None = "unit-lib", paths: tuple[str, ...] = (),
            roots: tuple[str, ...] = ()) -> Fact:
    return _structure(FactKind.LIBRARY, name, unit, True, paths, roots, False, None)


def link(source: Fact, target: Fact) -> Fact:
    ends = {"input": source.native_identity, "output": target.native_identity}
    evidence = cite(record("job_artifact_indexing", "artifact_relationships", "LINKS_INTO",
                           f"rel:{source.name}:{target.name}"), Basis.DECLARED, "structure.link_relation")
    return Fact(FactKind.LINK, ends, f"{source.name} -> {target.name}", Basis.DECLARED, (evidence,), ends)


def site(interaction: Interaction, path: str, line: int = 1, *, unit: str | None = None,
         basis: Basis = Basis.VERIFIED_SEMANTIC, source_class: str | None = None, symbol: str | None = "handler") -> Fact:
    evidence = cite(record("job_code_graph_index", "code_graph_facts", "entry_point",
                           f"ent:{interaction.value}:{path}:{line}", at=span(path, line)), basis, "graph.fixture")
    identity = {"interaction": interaction.value, "path": path, "start_line": line, "enclosing_symbol": symbol}
    return Fact(FactKind.INTERACTION, identity, f"{interaction.value} {path}:{line}", basis, (evidence,), {
        "interaction": interaction.value, "path": path, "source_class": source_class, "sink_class": None,
        "callee": None, "enclosing_symbol": symbol, "build_unit_id": unit, "component_id": None})


def built(*facts: Fact, limits: Limits = LIMITS) -> Assembly:
    return assemble((LaneResult(tuple(facts)),), reference(), limits)


def pid(fact: Fact) -> str:
    return element_id("proc", fact.native_identity)


def kinds_about(assembly: Assembly, subject: str) -> set[UnknownKind]:
    return {item.kind for item in assembly.unknowns if subject in item.subject_ids}


def test_external_entity_and_boundary_are_derived_from_an_evidenced_crossing() -> None:
    server, receive = process("server"), site(Interaction.NETWORK_RECEIVE, "server/net.c", 40, source_class="remote")
    assembly = built(server, receive)

    proc, peer = sorted(assembly.elements, key=lambda item: item.kind is not ElementKind.PROCESS)
    assert (proc.id, proc.kind, proc.name_basis, proc.basis) == (pid(server), ElementKind.PROCESS,
                                                                 NameBasis.ARTIFACT_NAME, Basis.DECLARED)
    assert proc.attributes["built"] is True and proc.attributes["artifact_path"] == "bin/server"
    assert (peer.kind, peer.name, peer.name_basis, peer.basis) == (
        ElementKind.EXTERNAL_ENTITY, "Remote network peer", NameBasis.DERIVED, Basis.DERIVED)
    assert peer.id == element_id("ext", {"process": proc.id, "key": "remote_network_peer"})
    assert peer.evidence == receive.evidence  # the crossing is the entity's evidence

    (flow,), (boundary,) = assembly.flows, assembly.boundaries
    assert (flow.source, flow.target, flow.interaction) == (peer.id, proc.id, Interaction.NETWORK_RECEIVE)
    assert flow.basis is Basis.VERIFIED_SEMANTIC and flow.evidence == receive.evidence
    assert dict(flow.attributes) == {"direction": "inbound", "site_count": 1}
    assert flow.crosses == (boundary.id,)
    assert (boundary.kind, boundary.inside, boundary.basis) == (BoundaryKind.NETWORK, (proc.id,), Basis.DERIVED)
    assert boundary.evidence == flow.evidence

    (entry,) = assembly.entry_points
    assert entry.id == element_id("ep", {"process": proc.id, "fact": receive.native_identity})
    assert (entry.process, entry.source_class, entry.enclosing_symbol) == (proc.id, "remote", "handler")
    (actor,) = assembly.actors
    assert actor.external_entity == peer.id and actor.evidence == peer.evidence
    assert kinds_about(assembly, proc.id) == {
        UnknownKind.RUNTIME_ROLE_UNKNOWN, UnknownKind.DEPLOYMENT_NOT_DESCRIBED, UnknownKind.PEER_UNIDENTIFIED,
        UnknownKind.PROTOCOL_UNKNOWN, UnknownKind.AUTHENTICATION_NOT_LOCATED}
    assert assembly.gaps == ()


def test_outbound_crossing_runs_from_the_process_and_is_no_entry_point() -> None:
    client = process("client")
    assembly = built(client, site(Interaction.NETWORK_CONNECT, "client/http.c", 9))

    (flow,) = assembly.flows
    assert flow.source == pid(client) and flow.attributes["direction"] == "outbound"
    assert [item.name for item in assembly.elements if item.kind is ElementKind.EXTERNAL_ENTITY] == [
        "Unidentified remote service"]
    assert assembly.entry_points == ()


def test_no_boundary_exists_without_a_crossing_flow() -> None:
    facts = [process("server"), process("tool", unit="unit-b", roots=("tools/",)),
             site(Interaction.NETWORK_LISTEN, "server/main.c", 5), site(Interaction.NETWORK_RECEIVE, "server/net.c", 8),
             site(Interaction.FILE_READ, "tools/load.c", 3), site(Interaction.DATASTORE_QUERY, "server/db.c", 4),
             site(Interaction.ARGUMENT_READ, "server/main.c", 1)]
    for limits in (LIMITS, Limits(max_flows=1), Limits(max_flows=2)):
        assembly = built(*facts, limits=limits)
        crossed = {boundary for flow in assembly.flows for boundary in flow.crosses}
        assert {boundary.id for boundary in assembly.boundaries} == crossed
        elements = {item.id for item in assembly.elements}
        for boundary in assembly.boundaries:
            flows = [flow for flow in assembly.flows if boundary.id in flow.crosses]
            assert flows and set(boundary.inside) <= elements
            assert {item.ref for item in boundary.evidence} <= {item.ref for flow in flows for item in flow.evidence}
        for flow in assembly.flows:
            assert {flow.source, flow.target} <= elements
    full = built(*facts)
    assert len(full.flows) == 5 and len(full.boundaries) == 3  # the two network flows share one boundary
    assert sorted(item.kind for item in full.boundaries) == [BoundaryKind.FILE_CONTENT, BoundaryKind.LOCAL_USER,
                                                             BoundaryKind.NETWORK]


def test_library_folds_transitively_and_an_unlinked_library_is_an_unknown() -> None:
    server = process("server")
    core, net, loose = library("core"), library("net"), library("loose")
    assembly = built(server, core, net, loose, link(net, core), link(core, net), link(core, server))

    (element,) = assembly.elements  # libraries are never elements
    assert element.id == pid(server) and element.attributes["libraries"] == ("core", "net")
    statements = [item for item in assembly.unknowns if item.statement.startswith("library ")]
    assert [(item.kind, item.statement, item.subject_ids) for item in statements] == [
        (UnknownKind.RUNTIME_ROLE_UNKNOWN, "library loose is not shown to link into any process", ())]
    assert statements[0].would_resolve == ("job_artifact_indexing/artifact_relationships",
                                           "job_cpp_compiled_analysis/cpp_build_graph")


def _owners(assembly: Assembly, fact: Fact, candidates: list[Fact]) -> list[str]:
    entries = {item.id for item in assembly.entry_points}
    return [item.name for item in candidates
            if element_id("ep", {"process": pid(item), "fact": fact.native_identity}) in entries]


def test_interaction_is_owned_by_build_unit_then_source_path_then_longest_root() -> None:
    whole = process("whole", unit="unit-a", roots=("",))
    listed = process("listed", unit="unit-b", paths=("shared/io.c",), roots=("b/",))
    deep = process("deep", unit="unit-c", roots=("b/deep/",))
    candidates = [whole, listed, deep]
    by_unit = site(Interaction.NETWORK_RECEIVE, "b/deep/x.c", 1, unit="unit-a")
    by_path = site(Interaction.NETWORK_RECEIVE, "shared/io.c", 2)
    by_longest_root = site(Interaction.NETWORK_RECEIVE, "b/deep/y.c", 3)
    by_root = site(Interaction.NETWORK_RECEIVE, "b/z.c", 4)
    by_target_root = site(Interaction.NETWORK_RECEIVE, "other/q.c", 5)
    unknown_unit = site(Interaction.NETWORK_RECEIVE, "b/deep/w.c", 6, unit="unit-missing")
    assembly = built(*candidates, by_unit, by_path, by_longest_root, by_root, by_target_root, unknown_unit)

    assert _owners(assembly, by_unit, candidates) == ["whole"]  # the build unit wins over the deeper root
    assert _owners(assembly, by_path, candidates) == ["listed"]  # a listed source wins over the "" root
    assert _owners(assembly, by_longest_root, candidates) == ["deep"]
    assert _owners(assembly, by_root, candidates) == ["listed"]
    assert _owners(assembly, by_target_root, candidates) == ["whole"]  # "" matches everything and is weakest
    assert _owners(assembly, unknown_unit, candidates) == ["deep"]  # a unit nothing declares falls through
    assert len(assembly.entry_points) == 6


def test_unowned_interactions_aggregate_into_unknowns() -> None:
    server = process("server", roots=("src/",))
    orphans = [site(Interaction.NETWORK_RECEIVE, "vendor/a.c", 1), site(Interaction.NETWORK_RECEIVE, "vendor/b.c", 2),
               site(Interaction.NETWORK_RECEIVE, "vendor/sub/c.c", 3), site(Interaction.FILE_READ, "tools/t.c", 4)]
    assembly = built(server, *orphans)

    unresolved = sorted(item.statement for item in assembly.unknowns
                        if item.kind is UnknownKind.FLOW_ENDPOINT_UNRESOLVED)
    assert unresolved == ["1 file_read interaction sites under tools are not attributed to any process",
                          "3 network_receive interaction sites under vendor are not attributed to any process"]
    assert assembly.flows == () and assembly.entry_points == () and assembly.boundaries == ()
    assert [item.id for item in assembly.elements] == [pid(server)]
    assert UnknownKind.BOUNDARY_NOT_ESTABLISHED in kinds_about(assembly, pid(server))


def test_interactions_of_an_unlinked_library_are_unowned() -> None:
    assembly = built(process("server", roots=("src/",)), library("loose", roots=("lib/",)),
                     site(Interaction.NETWORK_RECEIVE, "lib/net.c", 1))

    assert assembly.flows == ()
    assert [item.statement for item in assembly.unknowns if item.kind is UnknownKind.FLOW_ENDPOINT_UNRESOLVED] == [
        "1 network_receive interaction sites under lib are not attributed to any process"]


def test_shared_library_interaction_reaches_every_linking_process() -> None:
    server, client = process("server", roots=("server/",)), process("client", unit="unit-b", roots=("client/",))
    common, inner = library("common", roots=("common/",)), library("inner", roots=("inner/",))
    shared = site(Interaction.NETWORK_RECEIVE, "inner/packet.c", 12)
    assembly = built(server, client, common, inner, link(inner, common), link(common, server), link(common, client),
                     shared)

    assert _owners(assembly, shared, [server, client]) == ["server", "client"]
    assert sorted(flow.target for flow in assembly.flows) == sorted([pid(server), pid(client)])
    assert all(flow.attributes["site_count"] == 1 and flow.evidence == shared.evidence for flow in assembly.flows)
    assert len({flow.source for flow in assembly.flows}) == 2  # an external entity per process
    assert len(assembly.boundaries) == 2 and len(assembly.actors) == 2


def test_datastore_interaction_yields_a_store_without_a_boundary_and_an_unknown() -> None:
    server = process("server")
    assembly = built(server, site(Interaction.DATASTORE_QUERY, "server/db.c", 7),
                     site(Interaction.DATASTORE_QUERY, "server/db.c", 30), site(Interaction.FILE_WRITE, "server/log.c", 2))

    stores = {item.name: item for item in assembly.elements if item.kind is ElementKind.DATA_STORE}
    assert sorted(stores) == ["Data store queried by server", "Files written by server"]
    assert all(item.basis is Basis.DERIVED and item.name_basis is NameBasis.DERIVED for item in stores.values())
    queried = stores["Data store queried by server"]
    assert queried.id == element_id("store", {"process": pid(server), "interaction": "datastore_query"})
    (flow,) = [item for item in assembly.flows if item.target == queried.id]
    assert flow.source == pid(server) and flow.crosses == () and flow.attributes["site_count"] == 2
    assert assembly.boundaries == () and assembly.actors == () and assembly.entry_points == ()
    for store in stores.values():
        (about,) = [item for item in assembly.unknowns if store.id in item.subject_ids]
        assert about.kind is UnknownKind.DATASTORE_UNIDENTIFIED
        assert about.would_resolve == ("job_dependency_intelligence/dependency_context",
                                       "job_deployment_inventory/deployment_inventory")
    assert UnknownKind.BOUNDARY_NOT_ESTABLISHED in kinds_about(assembly, pid(server))


def _rich_facts() -> list[Fact]:
    server, client = process("server", roots=("server/",)), process("client", unit="unit-b", roots=("client/",))
    common, loose = library("common", roots=("common/",)), library("loose")
    weak = site(Interaction.NETWORK_RECEIVE, "server/net.c", 40, basis=Basis.OBSERVED_SYNTAX)
    return [server, client, process("server", roots=("server/",), entity="ent:second-reading"), common, loose,
            link(common, server), link(common, client), weak,
            site(Interaction.NETWORK_RECEIVE, "server/net.c", 40), site(Interaction.NETWORK_LISTEN, "server/main.c", 5),
            site(Interaction.NETWORK_CONNECT, "client/http.c", 9), site(Interaction.FILE_READ, "common/config.c", 3),
            site(Interaction.DATASTORE_QUERY, "server/db.c", 7), site(Interaction.PROCESS_SPAWN, "client/run.c", 2),
            site(Interaction.LOCAL_IPC, "client/ipc.c", 4), site(Interaction.ENVIRONMENT_READ, "vendor/env.c", 1),
            site(Interaction.ARGUMENT_READ, "client/main.c", 1, basis=Basis.OBSERVED_SYNTAX)]


def test_assembly_is_independent_of_lane_and_fact_order() -> None:
    facts = _rich_facts()
    expected = canonical(built(*facts))
    assert len(built(*facts).flows) == 9 and len(built(*facts).elements) == 2 + 7
    for seed in range(6):
        shuffled = list(facts)
        random.Random(seed).shuffle(shuffled)
        cut = seed * 3
        lanes = [LaneResult(tuple(shuffled[:cut])), LaneResult(tuple(shuffled[cut:]))]
        if seed % 2:
            lanes.reverse()
        assert canonical(assemble(lanes, reference(), LIMITS)) == expected


def test_facts_of_one_identity_merge_with_the_strongest_basis() -> None:
    assembly = built(*_rich_facts())
    server = next(item for item in assembly.elements if item.name == "server")
    assert len(server.evidence) == 2  # two readings of one process identity, one element
    receive = next(item for item in assembly.flows if item.interaction is Interaction.NETWORK_RECEIVE)
    assert receive.basis is Basis.VERIFIED_SEMANTIC and receive.attributes["site_count"] == 1
    assert [item.basis for item in receive.evidence] == [Basis.VERIFIED_SEMANTIC]  # one reference, strongest reading
    for records in (assembly.elements, assembly.flows, assembly.boundaries, assembly.entry_points, assembly.actors,
                    assembly.unknowns):
        assert [item.id for item in records] == sorted({item.id for item in records})


def test_only_catalog_facts_yield_processes_with_role_and_boundary_unknowns() -> None:
    tool = process("tool", built=False)
    checker = process("checker", unit="unit-b", built=False, test_only=True)
    assembly = built(tool, checker)

    assert sorted(item.id for item in assembly.elements) == sorted([pid(tool), pid(checker)])
    for element in assembly.elements:
        assert (element.kind, element.basis, element.name_basis) == (ElementKind.PROCESS, Basis.DECLARED,
                                                                     NameBasis.DECLARED_NAME)
        assert element.attributes["built"] is False and element.attributes["artifact_path"] is None
        assert kinds_about(assembly, element.id) == {
            UnknownKind.RUNTIME_ROLE_UNKNOWN, UnknownKind.DEPLOYMENT_NOT_DESCRIBED,
            UnknownKind.BOUNDARY_NOT_ESTABLISHED}
    assert next(item for item in assembly.elements if item.id == pid(checker)).attributes["test_only"] is True
    assert "test_only" not in next(item for item in assembly.elements if item.id == pid(tool)).attributes
    assert (assembly.flows, assembly.boundaries, assembly.entry_points, assembly.actors, assembly.gaps) == ((),) * 5
    role = next(item for item in assembly.unknowns if item.kind is UnknownKind.RUNTIME_ROLE_UNKNOWN
                and pid(tool) in item.subject_ids)
    assert role.statement == ("whether tool runs as a service, a command-line tool or a test helper "
                              "is not established")
    deployment = next(item for item in assembly.unknowns if item.kind is UnknownKind.DEPLOYMENT_NOT_DESCRIBED)
    assert deployment.would_resolve == ("job_deployment_inventory/deployment_inventory",)


def test_no_facts_yield_an_empty_model_with_one_unknown() -> None:
    for lanes in ((), (LaneResult(),)):
        assembly = assemble(lanes, reference(), LIMITS)
        (only,) = assembly.unknowns
        assert only.kind is UnknownKind.NO_ELEMENT_ESTABLISHED and only.subject_ids == ()
        assert only.would_resolve == ("job_artifact_indexing/artifact_catalog", "job_target_catalog/build_units")
        assert (assembly.elements, assembly.flows, assembly.boundaries, assembly.entry_points, assembly.actors,
                assembly.gaps) == ((),) * 6


def test_interactions_without_any_process_are_unowned_and_no_element_exists() -> None:
    assembly = built(site(Interaction.NETWORK_RECEIVE, "src/net.c", 1, unit="unit-a"))

    assert assembly.elements == () and assembly.flows == ()
    assert sorted(item.kind for item in assembly.unknowns) == [UnknownKind.FLOW_ENDPOINT_UNRESOLVED,
                                                               UnknownKind.NO_ELEMENT_ESTABLISHED]


def test_flow_and_entry_point_limits_are_truncated_gaps() -> None:
    facts = [process("server"), site(Interaction.FILE_READ, "a.c", 1, basis=Basis.OBSERVED_SYNTAX),
             site(Interaction.NETWORK_RECEIVE, "b.c", 2), site(Interaction.ARGUMENT_READ, "c.c", 3,
                                                               basis=Basis.OBSERVED_SYNTAX),
             site(Interaction.ARGUMENT_READ, "d.c", 4, basis=Basis.OBSERVED_SYNTAX)]
    full = built(*facts)
    assert (len(full.flows), len(full.entry_points), full.gaps) == (3, 4, ())

    assembly = built(*facts, limits=Limits(max_flows=1, max_entry_points=2))
    (flow,) = assembly.flows
    assert flow.interaction is Interaction.NETWORK_RECEIVE  # the strongest basis is kept first
    assert len(assembly.boundaries) == 1 and len(assembly.elements) == 2
    assert len(assembly.entry_points) == 2
    assert assembly.entry_points[0].id < assembly.entry_points[1].id
    assert Basis.VERIFIED_SEMANTIC in {item.basis for item in assembly.entry_points}
    assert sorted((gap["code"], gap["scope_id"], gap["unit_id"]) for gap in assembly.gaps) == [
        (GapCode.TRUNCATED.value, "assembly.max_entry_points", "assembly.dfd"),
        (GapCode.TRUNCATED.value, "assembly.max_flows", "assembly.dfd")]
