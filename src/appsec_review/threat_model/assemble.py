"""DFD assembly of the generated threat model (T-107, step ``assembly.dfd``).

Joins lane facts into elements, flows, trust boundaries, entry points and actors; everything that
does not join becomes an ``Unknown``. Design: docs/architecture/dfd-and-threat-model-generation.md
sections 6.2, 6.3, 6.4 and 7.1. ``assemble`` is a pure function: no file, no shard, no model. Names
that come from the target (artifact, library and path names) are carried as values only; every id is
derived from native identities.

Rules, in the order they are applied:

- Process facts of one native identity are one process element. Libraries fold into the processes
  they link into, transitively; a library that reaches no process is not an element but a
  ``runtime_role_unknown``. A link's ``output`` identity names every process or library of that
  identity other than the linking library itself (a process and a library may share an identity).
- An interaction fact is owned through the first of three rules that matches any process or library:
  equal ``build_unit_id``, its ``path`` among the ``source_paths``, the longest ``source_roots``
  prefix of its ``path``. Every process or library matching at that rule owns it, and a library
  stands for the processes it folds into. A fact that reaches no process this way is unowned;
  unowned facts are counted per interaction and first path segment in ``flow_endpoint_unresolved``
  unknowns.
- An owned interaction with a boundary rule yields an external entity per process and external key,
  one flow per process, entity and interaction, and one boundary per process and boundary kind. A
  boundary is built only from the flows that cross it, after the flow bound was applied, so it never
  exists without one. An interaction without a boundary rule yields a data store, a flow without a
  crossing and a ``datastore_unidentified`` unknown.
- Entry points are the owned inbound interaction sites, one per site and owning process.
- An actor is offered per external entity with the attacker positions the crosswalk lists for the
  templates of its flows. They are candidates for a reader; nothing here asserts a position.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.threat_model.contract import (
    BASIS_PRECEDENCE, Actor, Basis, Boundary, BoundaryKind, Element, ElementKind, EntryPoint, EvidenceRef, Fact,
    FactKind, Flow, Interaction, LaneResult, Limits, NameBasis, Unknown, UnknownKind, canonical, element_id,
    merge_evidence, strongest, unknown,
)
from appsec_review.threat_model.reference import Reference
from appsec_review.threat_model.view import truncated_gap

FLOW_BOUND = "assembly.max_flows"
ENTRY_POINT_BOUND = "assembly.max_entry_points"
INBOUND, OUTBOUND = "inbound", "outbound"

RESOLVE_LINKS = ("job_artifact_indexing/artifact_relationships", "job_cpp_compiled_analysis/cpp_build_graph")
RESOLVE_FIRST_ELEMENT = ("job_target_catalog/build_units", "job_artifact_indexing/artifact_catalog")
RESOLVE_OWNER = ("job_target_catalog/build_units", "job_artifact_indexing/artifact_catalog",
                 "job_cpp_compiled_analysis/cpp_build_graph")
RESOLVE_STORE = ("job_dependency_intelligence/dependency_context", "job_deployment_inventory/deployment_inventory")
RESOLVE_DEPLOYMENT = ("job_deployment_inventory/deployment_inventory",)
RESOLVE_INTERACTIONS = ("job_code_graph_index/code_graph_facts", "job_tree_sitter_ast/tree_sitter_ast")
STORE_NAMES = {Interaction.DATASTORE_QUERY: "Data store queried by {name}",
               Interaction.FILE_WRITE: "Files written by {name}"}


@dataclass(frozen=True, slots=True)
class Assembly:
    """The joined model. ``gaps`` holds only the gaps assembly created; lane gaps are the caller's."""
    elements: tuple[Element, ...] = ()
    flows: tuple[Flow, ...] = ()
    boundaries: tuple[Boundary, ...] = ()
    entry_points: tuple[EntryPoint, ...] = ()
    actors: tuple[Actor, ...] = ()
    unknowns: tuple[Unknown, ...] = ()
    gaps: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class _Thing:
    """The facts of one process or library identity, merged."""
    kind: FactKind
    key: bytes
    identity: Any
    name: str
    facts: tuple[Fact, ...]
    units: frozenset[str]
    paths: frozenset[str]
    roots: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Site:
    """The facts of one interaction identity, merged."""
    identity: Any
    interaction: Interaction
    path: str | None
    build_unit_id: str | None
    source_class: str | None
    enclosing_symbol: str | None
    basis: Basis
    evidence: tuple[EvidenceRef, ...]


@dataclass(slots=True)
class _Crossing:
    """One flow in the making: a process, the derived element beyond it and the sites that show it."""
    process: str
    peer: str
    peer_kind: ElementKind
    peer_name: str
    peer_attributes: Mapping[str, Any]
    interaction: Interaction
    direction: str
    boundary_kind: BoundaryKind | None
    sites: list[_Site] = field(default_factory=list)


def bounded_evidence(references: Iterable[EvidenceRef], limit: int) -> tuple[EvidenceRef, ...]:
    """``merge_evidence`` made independent of arrival order when one reference has two readings."""
    ordered = sorted(references, key=lambda item: (BASIS_PRECEDENCE.index(item.basis), item.rule, canonical(item)),
                     reverse=True)  # merge_evidence keeps the last of equal references: the strongest
    return merge_evidence(tuple(ordered), limit=limit)


def _rank(basis: Basis, identity: str) -> tuple[int, str]:
    return (BASIS_PRECEDENCE.index(basis), identity)


def _texts(values: Any) -> frozenset[str]:
    return frozenset(item for item in values or () if isinstance(item, str))


def _grouped(facts: Sequence[Fact], kind: FactKind) -> dict[bytes, tuple[Fact, ...]]:
    groups: dict[bytes, list[Fact]] = {}
    for fact in facts:
        if fact.kind is kind:
            groups.setdefault(canonical(fact.native_identity), []).append(fact)
    return {key: tuple(sorted(groups[key], key=canonical)) for key in sorted(groups)}


def _things(facts: Sequence[Fact], kind: FactKind) -> dict[bytes, _Thing]:
    things = {}
    for key, group in _grouped(facts, kind).items():
        units = frozenset(unit for fact in group if isinstance(unit := fact.attributes.get("build_unit_id"), str))
        things[key] = _Thing(kind, key, group[0].native_identity, min(fact.name for fact in group), group, units,
                             frozenset().union(*(_texts(fact.attributes.get("source_paths")) for fact in group)),
                             frozenset().union(*(_texts(fact.attributes.get("source_roots")) for fact in group)))
    return things


def _sites(facts: Sequence[Fact], limit: int) -> list[_Site]:
    sites = []
    for group in _grouped(facts, FactKind.INTERACTION).values():
        lead = min(group, key=lambda fact: (BASIS_PRECEDENCE.index(fact.basis), canonical(fact)))
        read = lead.attributes.get
        sites.append(_Site(lead.native_identity, Interaction(read("interaction")), read("path"), read("build_unit_id"),
                           read("source_class"), read("enclosing_symbol"), strongest(*(fact.basis for fact in group)),
                           bounded_evidence((item for fact in group for item in fact.evidence), limit)))
    return sites


def _folds(processes: Mapping[bytes, _Thing], libraries: Mapping[bytes, _Thing],
           facts: Sequence[Fact]) -> dict[bytes, frozenset[bytes]]:
    """Library key to the keys of the processes it links into, directly or through other libraries."""
    edges: dict[bytes, set[bytes]] = {}
    for fact in facts:
        if fact.kind is FactKind.LINK and "input" in fact.attributes and "output" in fact.attributes:
            source, target = canonical(fact.attributes["input"]), canonical(fact.attributes["output"])
            if source in libraries:
                edges.setdefault(source, set()).add(target)
    folds = {}
    for library in libraries:
        seen, pending, reached = {library}, [library], set()
        while pending:
            for target in sorted(edges.get(pending.pop(), ())):
                if target in processes:
                    reached.add(target)
                if target in libraries and target not in seen:  # a cycle ends here
                    seen.add(target)
                    pending.append(target)
        folds[library] = frozenset(reached)
    return folds


class _Owners:
    """Rule 3: which processes own an interaction site."""

    def __init__(self, processes: Mapping[bytes, _Thing], libraries: Mapping[bytes, _Thing],
                 folds: Mapping[bytes, frozenset[bytes]]) -> None:
        self._by_unit: dict[str, set[bytes]] = {}
        self._by_path: dict[str, set[bytes]] = {}
        self._by_root: dict[str, set[bytes]] = {}
        for things in (processes, libraries):
            for key, thing in things.items():
                reached = folds[key] if thing.kind is FactKind.LIBRARY else frozenset((key,))
                for index, values in ((self._by_unit, thing.units), (self._by_path, thing.paths),
                                      (self._by_root, thing.roots)):
                    for value in values:
                        index.setdefault(value, set()).update(reached)
        self._roots = sorted(self._by_root, key=lambda root: (-len(root), root))

    def of(self, site: _Site) -> frozenset[bytes]:
        if site.build_unit_id is not None and site.build_unit_id in self._by_unit:
            return frozenset(self._by_unit[site.build_unit_id])
        if site.path is None:
            return frozenset()
        if site.path in self._by_path:
            return frozenset(self._by_path[site.path])
        for root in self._roots:  # longest first; "" matches every path and is last
            if site.path.startswith(root):
                return frozenset(self._by_root[root])
        return frozenset()


def _process(thing: _Thing, libraries: Sequence[str], limits: Limits) -> Element:
    facts = thing.facts
    built = any(fact.attributes.get("built") is True for fact in facts)
    attributes: dict[str, Any] = {
        "built": built,
        "build_unit_id": min(thing.units, default=None),
        "artifact_path": min((path for fact in facts if isinstance(path := fact.attributes.get("artifact_path"), str)),
                             default=None),
        "libraries": tuple(sorted(set(libraries))),
    }
    if any(fact.attributes.get("test_only") is True for fact in facts):
        attributes["test_only"] = True
    components = sorted(set().union(*(_texts(fact.attributes.get("component_ids")) for fact in facts)))
    return Element(element_id("proc", thing.identity), ElementKind.PROCESS, thing.name,
                   NameBasis.ARTIFACT_NAME if built else NameBasis.DECLARED_NAME,
                   strongest(*(fact.basis for fact in facts)),
                   bounded_evidence((item for fact in facts for item in fact.evidence),
                                    limits.max_evidence_refs_per_element),
                   attributes, tuple(components))


def _flow(crossing: _Crossing, limits: Limits) -> Flow:
    identity = element_id("flow", {"process": crossing.process, "peer": crossing.peer,
                                   "interaction": crossing.interaction.value})
    inbound = crossing.direction == INBOUND
    crosses = () if crossing.boundary_kind is None else (_boundary_id(crossing.process, crossing.boundary_kind),)
    return Flow(identity, crossing.peer if inbound else crossing.process, crossing.process if inbound else crossing.peer,
                crossing.interaction, strongest(*(site.basis for site in crossing.sites)),
                bounded_evidence((item for site in crossing.sites for item in site.evidence),
                                 limits.max_evidence_refs_per_element),
                crosses, None, {"direction": crossing.direction, "site_count": len(crossing.sites)})


def _boundary_id(process: str, kind: BoundaryKind) -> str:
    return element_id("tb", {"process": process, "kind": kind.value})


def _bounded(records: list[Any], limit: int, bound: str, unit_id: str, gaps: list[Mapping[str, Any]]) -> list[Any]:
    """Strongest basis first, then id; a reached bound is a ``truncated`` gap."""
    if len(records) <= limit:
        return records
    gaps.append(truncated_gap(bound, limit, unit_id=unit_id))
    return sorted(records, key=lambda item: _rank(item.basis, item.id))[:limit]


def _by_id(records: Iterable[Any]) -> tuple[Any, ...]:
    return tuple(sorted({item.id: item for item in records}.values(), key=lambda item: item.id))


def assemble(lane_results: Sequence[LaneResult], reference: Reference, limits: Limits, *,
             unit_id: str = "assembly.dfd") -> Assembly:
    """Join lane facts into the DFD records; the result does not depend on the order of its inputs."""
    facts = [fact for result in lane_results for fact in result.facts]
    limit = limits.max_evidence_refs_per_element
    processes, libraries = _things(facts, FactKind.PROCESS), _things(facts, FactKind.LIBRARY)
    folds = _folds(processes, libraries, facts)
    owners = _Owners(processes, libraries, folds)
    unknowns: list[Unknown] = []
    gaps: list[Mapping[str, Any]] = []

    folded: dict[bytes, list[str]] = {}
    for key, library in libraries.items():
        for process in folds[key]:
            folded.setdefault(process, []).append(library.name)
        if not folds[key]:
            unknowns.append(unknown(UnknownKind.RUNTIME_ROLE_UNKNOWN,
                                    f"library {library.name} is not shown to link into any process",
                                    would_resolve=RESOLVE_LINKS))
    elements = {key: _process(thing, folded.get(key, ()), limits) for key, thing in processes.items()}
    names = {element.id: element.name for element in elements.values()}

    crossings: dict[tuple[str, str, str], _Crossing] = {}
    entry_points: list[EntryPoint] = []
    unowned: dict[tuple[str, str], int] = {}
    for site in _sites(facts, limit):
        owning = sorted(elements[key].id for key in owners.of(site))
        if not owning:
            segment = site.path.split("/", 1)[0] if site.path else "an unstated path"
            unowned[(site.interaction.value, segment)] = unowned.get((site.interaction.value, segment), 0) + 1
            continue
        rule = reference.boundary_for(site.interaction)
        for process in owning:
            if rule is not None:
                peer = element_id("ext", {"process": process, "key": rule.external_key})
                made = _Crossing(process, peer, ElementKind.EXTERNAL_ENTITY, rule.external_name,
                                 {"external_key": rule.external_key, "process": process}, site.interaction,
                                 rule.direction, rule.boundary_kind)
                if rule.direction == INBOUND:
                    entry_points.append(EntryPoint(
                        element_id("ep", {"process": process, "fact": site.identity}), process, site.interaction,
                        site.source_class, site.enclosing_symbol, site.basis, site.evidence))
            else:
                peer = element_id("store", {"process": process, "interaction": site.interaction.value})
                name = STORE_NAMES.get(site.interaction, "Store reached by {name} through " + site.interaction.value)
                made = _Crossing(process, peer, ElementKind.DATA_STORE, name.format(name=names[process]),
                                 {"interaction": site.interaction.value, "process": process}, site.interaction,
                                 OUTBOUND, None)
            crossings.setdefault((process, peer, site.interaction.value), made).sites.append(site)

    for (interaction, segment), count in sorted(unowned.items()):
        unknowns.append(unknown(
            UnknownKind.FLOW_ENDPOINT_UNRESOLVED,
            f"{count} {interaction} interaction sites under {segment} are not attributed to any process",
            would_resolve=RESOLVE_OWNER))

    by_flow = {(flow := _flow(crossing, limits)).id: (flow, crossing) for crossing in crossings.values()}
    flows = _bounded([flow for flow, _ in by_flow.values()], limits.max_flows, FLOW_BOUND, unit_id, gaps)
    entry_points = _bounded(list(_by_id(entry_points)), limits.max_entry_points, ENTRY_POINT_BOUND, unit_id, gaps)

    peers: dict[str, list[Flow]] = {}
    crossed: dict[str, list[Flow]] = {}
    for flow in flows:
        peers.setdefault(by_flow[flow.id][1].peer, []).append(flow)
        for boundary in flow.crosses:
            crossed.setdefault(boundary, []).append(flow)

    derived: list[Element] = []
    actors: list[Actor] = []
    for peer, touching in sorted(peers.items()):
        crossing = by_flow[touching[0].id][1]
        evidence = bounded_evidence((item for flow in touching for item in flow.evidence), limit)
        derived.append(Element(peer, crossing.peer_kind, crossing.peer_name, NameBasis.DERIVED, Basis.DERIVED, evidence,
                               crossing.peer_attributes))
        if crossing.peer_kind is ElementKind.DATA_STORE:
            unknowns.append(unknown(UnknownKind.DATASTORE_UNIDENTIFIED,
                                    f"which store {crossing.peer_name} is, is not named by the evidence",
                                    subject_ids=(peer,), would_resolve=RESOLVE_STORE))
            continue
        positions: set[str] = set()
        for flow in touching:
            kind = by_flow[flow.id][1].boundary_kind
            for template in reference.templates_for(flow.interaction, kind, flow.attributes["direction"]):
                positions.update(reference.crosswalk_for(template.template_id)["attacker_positions"])
        actors.append(Actor(element_id("actor", peer), peer, tuple(sorted(positions)), evidence))

    boundaries: list[Boundary] = []
    kinds: dict[str, set[BoundaryKind]] = {}
    for boundary, crossing_flows in sorted(crossed.items()):
        crossing = by_flow[crossing_flows[0].id][1]
        kinds.setdefault(crossing.process, set()).add(crossing.boundary_kind)
        boundaries.append(Boundary(boundary, crossing.boundary_kind, (crossing.process,), Basis.DERIVED,
                                   bounded_evidence((item for flow in crossing_flows for item in flow.evidence), limit)))

    for process in sorted(elements.values(), key=lambda item: item.id):
        subject, name = (process.id,), process.name
        unknowns.append(unknown(
            UnknownKind.RUNTIME_ROLE_UNKNOWN,
            f"whether {name} runs as a service, a command-line tool or a test helper is not established",
            subject_ids=subject, would_resolve=RESOLVE_DEPLOYMENT))
        unknowns.append(unknown(UnknownKind.DEPLOYMENT_NOT_DESCRIBED,
                                f"where and how {name} is deployed is not described by any accepted input",
                                subject_ids=subject, would_resolve=RESOLVE_DEPLOYMENT))
        if process.id not in kinds:
            unknowns.append(unknown(UnknownKind.BOUNDARY_NOT_ESTABLISHED,
                                    f"no evidenced flow of {name} crosses a trust boundary",
                                    subject_ids=subject, would_resolve=RESOLVE_INTERACTIONS))
        if BoundaryKind.NETWORK in kinds.get(process.id, ()):
            unknowns.append(unknown(UnknownKind.PEER_UNIDENTIFIED,
                                    f"who the network peers of {name} are is not established",
                                    subject_ids=subject, would_resolve=RESOLVE_DEPLOYMENT))
            unknowns.append(unknown(UnknownKind.PROTOCOL_UNKNOWN,
                                    f"which protocol {name} speaks on the network is not established",
                                    subject_ids=subject, would_resolve=RESOLVE_DEPLOYMENT))
            unknowns.append(unknown(UnknownKind.AUTHENTICATION_NOT_LOCATED,
                                    f"where {name} authenticates a network peer is not located",
                                    subject_ids=subject, would_resolve=RESOLVE_INTERACTIONS))
    if not elements:
        unknowns.append(unknown(UnknownKind.NO_ELEMENT_ESTABLISHED,
                                "no process is established: no accepted input names an executable build point "
                                "or a built executable",
                                would_resolve=RESOLVE_FIRST_ELEMENT))

    return Assembly(_by_id((*elements.values(), *derived)), _by_id(flows), _by_id(boundaries), _by_id(entry_points),
                    _by_id(actors), _by_id(unknowns), tuple(gaps))
