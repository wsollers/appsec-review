"""The structure lane (T-107, ``facts.structure``): processes, libraries and links from build evidence.

Design: docs/architecture/dfd-and-threat-model-generation.md sections 4.1, 6.2 and 7. The lane is a
pure function over an ``EvidenceView``. It never opens a file, a shard or the target, and a name
read from the target is only ever a value in a fact: never code, a path to open, or an id.

What it reads, and the producer shapes it relies on (file:line at the commit this was written on):

``job_target_catalog/build_units`` - entity kind ``build_action``, one per build unit
(jobs/job_target_catalog/job.py:584-589; the payload is the whole build target).
  - ``build_unit_id``, ``root`` (jobs/build_discovery.py:717-724; ``"."`` is the target root);
  - ``build_points`` (jobs/build_discovery.py:518), each ``{name, kind, evidence, sources, ...}``
    (jobs/build_points.py:78-85), and ``product_type`` on an Xcode ``native_target``
    (jobs/build_points.py:1043-1044).
  - Executable point kinds: ``executable`` (CMake :419-420, meson :979), ``bin`` (Cargo :698),
    ``main_package`` (Go :769), ``program`` (automake :1014), and the test executables ``test``
    (Cargo :709) and ``test_program`` (automake :1015).
  - Library point kinds: ``static_library``, ``shared_library``, ``module_library``, ``library``
    (CMake :422-424, meson :979-980), ``lib`` (Cargo :694), ``libtool_library`` (automake :1014).
  - The catalog publishes no dependency between build points, so no link is ever *declared*.

``job_target_catalog/components`` - entity kind ``component``; payload ``component_id``, ``root``
(jobs/job_target_catalog/job.py:297-303 and :445-449).

``job_artifact_indexing/artifact_catalog`` - entity kinds ``executable`` and ``library``
(jobs/job_artifact_indexing/job.py:69-85); payload ``workspace_path``, ``build_unit_id``
(:616-630). A target-intake artifact (``artifact_origin == "target-intake"``, :648-654) carries no
build unit, was not built by an accepted build, and is not a process here.

``job_artifact_indexing/artifact_relationships`` - relation ``LINKS_INTO`` from a link input to the
linked artifact, both artifact-catalog entity ids (jobs/job_artifact_indexing/job.py:864-890).

``job_language_build/build_actions`` - entity kinds ``executable`` and ``library``; payload
``workspace_path``, ``build_unit_id`` (jobs/job_language_build/job.py:1754-1765).

``job_cpp_compiled_analysis/cpp_build_graph`` - entity kinds ``executable`` and ``library`` with
payload ``path`` and ``project_id`` (jobs/job_cpp_compiled_analysis/job.py:481-491; ``project_id``
is ``cpp:<root>``, :908, and no ``build_unit_id`` is published), ``compile_unit`` with payload
``target_path`` (:466-475), and relations ``COMPILES_TO`` (compile unit to object, :492-499) and
``LINKS_INTO`` (link input to output, :500-509).

Relation convention: an index relation is not an entity. The job's view presents a relation as an
``EvidenceRecord`` whose ``entity_kind`` is the relation type (``LINKS_INTO``, ``COMPILES_TO``) and
whose payload is ``{"source_id": <entity id>, "target_id": <entity id>, ...relation payload}``;
``view.entities(producer, output_kind, "LINKS_INTO", limit=...)`` lists them.

Decisions:

- Every fact here has ``Basis.DECLARED``: ``VERIFIED_SEMANTIC`` is reserved for code-graph facts.
  The ``built`` attribute, not the basis, separates an artifact an accepted build produced
  (``True``) from a build point that is only declared (``False``).
- ``native_identity`` is ``{"build_unit_id", "name"}``. A process name is the artifact file name or
  build-point name without directory and without ``.exe``. A library name additionally loses a
  library suffix (``.a``, ``.la``, ``.lib``, ``.rlib``, ``.dll``, ``.dylib``, ``.so[.N...]``) and,
  only then, a leading ``lib``, so ``add_library(foo)`` and ``libfoo.a`` are one library. A declared
  and a built thing of one unit and name are therefore one fact carrying both citations.
- A ``cpp_build_graph`` artifact has no build unit. It joins the one fact of the same kind and name
  the other inputs established; with no such fact, or more than one, it is its own fact identified
  by ``{"project_id", "name"}`` with ``build_unit_id: None``.
- ``component_ids`` are the components whose root is the deepest one containing the unit root.
- ``test_only: True`` is set only from a build point of kind ``test`` or ``test_program``; no
  artifact producer publishes a test role, so it is otherwise omitted.
- A link is a ``LINKS_INTO`` relation from a library fact into a different process or library fact.
  A library with no such relation still yields its ``library`` fact and no link; unknowns are
  assembly's.
- Past ``max_processes`` the first processes in canonical identity order are kept, links into a
  dropped process are dropped with it, and the bound is a ``truncated`` gap.
- Index payloads are stored after ``retrieval.model.sanitize_producer_data``: a string holding a
  secret-like word arrives as ``"<redacted>"`` and deep nesting as ``"<truncated>"``. A build point
  or artifact whose name is such a marker is named ``redacted-name`` and identified by
  ``{"build_unit_id" | "project_id", "record"}``, where ``record`` is the entity id of the record
  that named it (``<entity id>#<index>`` for a build point, its position among the unit's build
  points), so two redacted names never become one process. Marker entries are dropped from the
  source paths. When any of this happened the lane reports one ``provenance_unavailable`` gap with
  scope ``structure.redacted`` and the number of names and paths affected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Mapping

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.retrieval.model import EntityKind, RelationKind
from appsec_review.threat_model.contract import (
    Basis, EvidenceRecord, EvidenceRef, Fact, FactKind, InputLedgerRow, LaneResult, Limits, canonical, cite,
    merge_evidence,
)
from appsec_review.threat_model.view import EvidenceView, empty_gap, open_input, truncated_gap, with_count

LANE = "structure"
BUILD_UNITS = ("job_target_catalog", "build_units")
COMPONENTS = ("job_target_catalog", "components")
ARTIFACT_CATALOG = ("job_artifact_indexing", "artifact_catalog")
ARTIFACT_RELATIONSHIPS = ("job_artifact_indexing", "artifact_relationships")
BUILD_ACTIONS = ("job_language_build", "build_actions")
CPP_BUILD_GRAPH = ("job_cpp_compiled_analysis", "cpp_build_graph")
INPUTS = tuple(sorted((BUILD_UNITS, COMPONENTS, ARTIFACT_CATALOG, ARTIFACT_RELATIONSHIPS, BUILD_ACTIONS,
                       CPP_BUILD_GRAPH)))

TEST_POINT_KINDS = frozenset({"test", "test_program"})
EXECUTABLE_POINT_KINDS = frozenset({"executable", "bin", "main_package", "program"}) | TEST_POINT_KINDS
LIBRARY_POINT_KINDS = frozenset({"static_library", "shared_library", "module_library", "library", "lib",
                                 "libtool_library"})
RULE_DECLARED = "structure.declared_build_point"
RULE_BUILT = "structure.built_artifact"
RULE_LINK = "structure.link_relation"
# What ``retrieval.model.sanitize_producer_data`` leaves in place of a withheld string.
INDEX_MARKERS = frozenset({"<redacted>", "<truncated>"})
REDACTED_NAME = "redacted-name"
REDACTED_SCOPE = "structure.redacted"

_ARTIFACT_KINDS = ((EntityKind.EXECUTABLE.value, FactKind.PROCESS), (EntityKind.LIBRARY.value, FactKind.LIBRARY))
_LIBRARY_SUFFIX = re.compile(r"(?:\.(?:a|la|lib|rlib|dll|dylib)|\.so(?:\.\d+)*)$", re.IGNORECASE)
_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass(slots=True)
class _Thing:
    kind: FactKind
    scope: str  # "build_unit_id" or "project_id"
    scope_id: str
    name: str
    evidence: list[EvidenceRef] = field(default_factory=list)
    artifact_paths: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    built: bool = False
    test_only: bool = False
    record: str | None = None  # set when the index withheld the name: the identity uses it instead

    @property
    def identity(self) -> dict[str, str]:
        if self.record is not None:
            return {self.scope: self.scope_id, "record": self.record}
        return {self.scope: self.scope_id, "name": self.name}


_Key = tuple[str, str, str, str]


@dataclass(slots=True)
class _Withheld:
    """How many names and paths the index had redacted or truncated."""
    count: int = 0


def _marked(value: str | None) -> bool:
    return value is not None and (value in INDEX_MARKERS or _file_name(value) in INDEX_MARKERS)


class _Reader:
    """Opens the declared inputs once and asks bounded questions of the readable ones."""

    def __init__(self, view: EvidenceView, limits: Limits, unit_id: str) -> None:
        self._view, self._limit, self._unit_id = view, limits.max_query_rows, unit_id
        self.rows: dict[tuple[str, str], InputLedgerRow] = {}
        self.counts: dict[tuple[str, str], int] = {}
        self.readable: set[tuple[str, str]] = set()
        self.input_gaps: list[Mapping[str, Any]] = []
        self.truncated: list[Mapping[str, Any]] = []
        for key in INPUTS:
            opened = open_input(view, *key, unit_id=unit_id)
            self.rows[key], self.counts[key] = opened.row, 0
            self.input_gaps.extend(opened.gaps)
            if opened.readable:
                self.readable.add(key)

    def query(self, key: tuple[str, str], kind: str) -> tuple[EvidenceRecord, ...]:
        if key not in self.readable:
            return ()
        page = self._view.entities(key[0], key[1], kind, limit=self._limit)
        self.counts[key] += len(page.records)
        if page.truncated:
            self.truncated.append(truncated_gap(f"{LANE}.{key[1]}.{kind}", self._limit, unit_id=self._unit_id))
        return tuple(sorted(page.records, key=lambda item: (item.entity_id, item.publication.sha256)))

    def ledger(self) -> tuple[InputLedgerRow, ...]:
        return tuple(with_count(self.rows[key], self.counts[key]) for key in INPUTS)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() and "\x00" not in value else None


def _relative(value: Any) -> str | None:
    """A target- or workspace-relative POSIX path as the producer wrote it, or ``None``."""
    text = _text(value)
    if text is None or "\\" in text or text.startswith("/") or _DRIVE.match(text):
        return None
    return None if any(part in {"", ".", ".."} for part in text.split("/")) else text


def _file_name(value: str) -> str:
    return value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _native_name(kind: FactKind, value: str) -> str | None:
    name = _file_name(value)
    if kind is FactKind.PROCESS:
        if name.lower().endswith(".exe"):
            name = name[:-4]
    else:
        stripped = _LIBRARY_SUFFIX.sub("", name)
        if stripped != name:
            name = stripped[3:] if stripped.startswith("lib") and len(stripped) > 3 else stripped
    return _text(name)


def _point_kind(point: Mapping[str, Any]) -> FactKind | None:
    kind = point.get("kind")
    if kind in EXECUTABLE_POINT_KINDS:
        return FactKind.PROCESS
    if kind in LIBRARY_POINT_KINDS:
        return FactKind.LIBRARY
    product = point.get("product_type")
    if kind == "native_target" and isinstance(product, str):
        if product.endswith((".application", ".tool")):
            return FactKind.PROCESS
        if ".library." in product or product.endswith(".framework"):
            return FactKind.LIBRARY
    return None


def _root_prefix(value: Any) -> str | None:
    """A unit or component root as a directory prefix: ``""`` for the target root, else ``dir/``."""
    if value in (".", ""):
        return ""
    path = _relative(value.rstrip("/") if isinstance(value, str) else value)
    return None if path is None else path + "/"


def _thing(things: dict[_Key, _Thing], kind: FactKind, scope: str, scope_id: str, name: str,
           record: str | None = None) -> _Thing:
    if record is None:
        return things.setdefault((kind.value, scope, scope_id, name), _Thing(kind, scope, scope_id, name))
    # A name cannot hold a NUL (``_text``), so a record key never meets a named thing's key.
    return things.setdefault((kind.value, scope, scope_id, "\x00" + record),
                             _Thing(kind, scope, scope_id, REDACTED_NAME, record=record))


def _declared(reader: _Reader, things: dict[_Key, _Thing], roots: dict[str, str], withheld: _Withheld) -> None:
    for record in reader.query(BUILD_UNITS, EntityKind.BUILD_ACTION.value):
        unit = _text(record.payload.get("build_unit_id"))
        if unit is None:
            continue
        root = _root_prefix(record.payload.get("root"))
        if root is not None:
            roots[unit] = root
        points = record.payload.get("build_points")
        for index, point in enumerate(points if isinstance(points, (list, tuple)) else ()):
            if not isinstance(point, Mapping):
                continue
            kind, raw = _point_kind(point), _text(point.get("name"))
            marked = _marked(raw)
            name = _native_name(kind, raw) if kind is not None and raw is not None else None
            if kind is None or name is None:
                continue
            withheld.count += marked
            thing = _thing(things, kind, "build_unit_id", unit, name,
                           f"{record.entity_id}#{index}" if marked else None)
            thing.evidence.append(cite(record, Basis.DECLARED, RULE_DECLARED))
            thing.test_only = thing.test_only or point.get("kind") in TEST_POINT_KINDS
            sources = point.get("sources")
            for source in sources if isinstance(sources, (list, tuple)) else ():
                if source in INDEX_MARKERS:
                    withheld.count += 1
                elif (path := _relative(source)) is not None:
                    thing.sources.add(path)


def _built(reader: _Reader, things: dict[_Key, _Thing], by_entity: dict[str, _Key], withheld: _Withheld) -> None:
    for key in (ARTIFACT_CATALOG, BUILD_ACTIONS):
        for entity_kind, kind in _ARTIFACT_KINDS:
            for record in reader.query(key, entity_kind):
                unit, path = _text(record.payload.get("build_unit_id")), _relative(record.payload.get("workspace_path"))
                name = _native_name(kind, path) if path is not None else None
                if unit is None or name is None or record.payload.get("artifact_origin") == "target-intake":
                    continue
                marked = _marked(path)
                withheld.count += marked
                _observe(_thing(things, kind, "build_unit_id", unit, name, record.entity_id if marked else None),
                         record, None if marked else path, by_entity)


def _observe(thing: _Thing, record: EvidenceRecord, path: str | None, by_entity: dict[str, _Key]) -> None:
    thing.built = True
    if path is not None:
        thing.artifact_paths.add(path)
    thing.evidence.append(cite(record, Basis.DECLARED, RULE_BUILT))
    by_entity[record.entity_id] = (thing.kind.value, thing.scope, thing.scope_id,
                                   thing.name if thing.record is None else "\x00" + thing.record)


def _compiled(reader: _Reader, things: dict[_Key, _Thing], by_entity: dict[str, _Key], withheld: _Withheld) -> None:
    """``cpp_build_graph`` artifacts: joined by unique name, else scoped to the producer's project."""
    established: dict[tuple[str, str], list[_Key]] = {}
    for key in sorted(things):
        established.setdefault((key[0], key[3]), []).append(key)
    for entity_kind, kind in _ARTIFACT_KINDS:
        for record in reader.query(CPP_BUILD_GRAPH, entity_kind):
            path = _relative(record.payload.get("path"))
            name = _native_name(kind, path) if path is not None else None
            if name is None:
                continue
            unit, project = _text(record.payload.get("build_unit_id")), _text(record.payload.get("project_id"))
            marked = _marked(path)
            identified = record.entity_id if marked else None  # a withheld name joins nothing by name
            matches = [] if marked else established.get((kind.value, name), [])
            if unit is not None:
                thing = _thing(things, kind, "build_unit_id", unit, name, identified)
            elif len(matches) == 1:
                thing = things[matches[0]]
            elif project is not None:
                thing = _thing(things, kind, "project_id", project, name, identified)
            else:
                continue
            withheld.count += marked
            _observe(thing, record, None if marked else path, by_entity)


def _endpoints(record: EvidenceRecord) -> tuple[str, str] | None:
    source, target = _text(record.payload.get("source_id")), _text(record.payload.get("target_id"))
    return None if source is None or target is None else (source, target)


def _compiled_sources(reader: _Reader, things: dict[_Key, _Thing], by_entity: dict[str, _Key],
                      links: tuple[EvidenceRecord, ...], withheld: _Withheld) -> None:
    """Sources of the compile units whose objects link into an established artifact."""
    unit_paths: dict[str, str] = {}
    for record in reader.query(CPP_BUILD_GRAPH, EntityKind.COMPILE_UNIT.value):
        path = _relative(record.payload.get("target_path"))
        if path in INDEX_MARKERS:
            withheld.count += 1
        elif path is not None:
            unit_paths[record.entity_id] = path
    compiled: dict[str, set[str]] = {}
    for record in reader.query(CPP_BUILD_GRAPH, RelationKind.COMPILES_TO.value):
        ends = _endpoints(record)
        if ends is not None and ends[0] in unit_paths:
            compiled.setdefault(ends[1], set()).add(unit_paths[ends[0]])
    for record in links:
        ends = _endpoints(record)
        if ends is not None and ends[0] in compiled and ends[1] in by_entity:
            things[by_entity[ends[1]]].sources.update(compiled[ends[0]])


def _component_ids(reader: _Reader) -> dict[str, list[str]]:
    by_root: dict[str, list[str]] = {}
    for record in reader.query(COMPONENTS, EntityKind.COMPONENT.value):
        identity, root = _text(record.payload.get("component_id")), _root_prefix(record.payload.get("root"))
        if identity is not None and root is not None:
            by_root.setdefault(root, []).append(identity)
    return by_root


def _fact(thing: _Thing, roots: Mapping[str, str], components: Mapping[str, list[str]], limits: Limits) -> Fact:
    root = roots.get(thing.scope_id) if thing.scope == "build_unit_id" else None
    containing = [prefix for prefix in components if root is not None and root.startswith(prefix)]
    deepest = max(containing, key=len, default=None)
    attributes: dict[str, Any] = {
        "build_unit_id": thing.scope_id if thing.scope == "build_unit_id" else None,
        "artifact_path": min(thing.artifact_paths, default=None),
        "component_ids": tuple(sorted(set(components[deepest]))) if deepest is not None else (),
        "source_paths": tuple(sorted(thing.sources)),
        "source_roots": (root,) if root is not None else (),
        "built": thing.built,
    }
    if thing.test_only:
        attributes["test_only"] = True
    return Fact(thing.kind, thing.identity, thing.name, Basis.DECLARED,
                merge_evidence(tuple(thing.evidence), limit=limits.max_evidence_refs_per_element), attributes)


def structure(view: EvidenceView, limits: Limits, *, unit_id: str = "facts.structure") -> LaneResult:
    """Process, library and link facts from the accepted build and artifact evidence in ``view``."""
    reader = _Reader(view, limits, unit_id)
    things: dict[_Key, _Thing] = {}
    roots: dict[str, str] = {}
    by_entity: dict[str, _Key] = {}
    withheld = _Withheld()
    _declared(reader, things, roots, withheld)
    _built(reader, things, by_entity, withheld)
    _compiled(reader, things, by_entity, withheld)
    relations = (reader.query(ARTIFACT_RELATIONSHIPS, RelationKind.LINKS_INTO.value),
                 reader.query(CPP_BUILD_GRAPH, RelationKind.LINKS_INTO.value))
    _compiled_sources(reader, things, by_entity, relations[1], withheld)
    components = _component_ids(reader)

    link_evidence: dict[tuple[_Key, _Key], list[EvidenceRef]] = {}
    for record in (*relations[0], *relations[1]):
        ends = _endpoints(record)
        if ends is None:
            continue
        source, target = by_entity.get(ends[0]), by_entity.get(ends[1])
        if source is not None and target is not None and source != target and source[0] == FactKind.LIBRARY.value:
            link_evidence.setdefault((source, target), []).append(cite(record, Basis.DECLARED, RULE_LINK))

    gaps = [*reader.input_gaps, *reader.truncated]
    if withheld.count:
        gaps.append(producer_gap(
            GapCode.PROVENANCE_UNAVAILABLE,
            f"{withheld.count} names or paths were redacted or truncated by the index; affected processes are "
            "identified by record, not by name", unit_id=unit_id, scope_id=REDACTED_SCOPE))
    processes = sorted((key for key in things if key[0] == FactKind.PROCESS.value),
                       key=lambda key: canonical(things[key].identity))
    dropped = set(processes[limits.max_processes:])
    if dropped:
        gaps.append(truncated_gap(f"{LANE}.max_processes", limits.max_processes, unit_id=unit_id))
    facts = [_fact(thing, roots, components, limits) for key, thing in things.items() if key not in dropped]
    for (source, target), evidence in link_evidence.items():
        if source in dropped or target in dropped:
            continue
        ends = {"input": things[source].identity, "output": things[target].identity}
        facts.append(Fact(FactKind.LINK, ends, f"{things[source].name} -> {things[target].name}", Basis.DECLARED,
                          merge_evidence(tuple(evidence), limit=limits.max_evidence_refs_per_element), ends))
    facts.sort(key=lambda fact: (fact.kind.value, canonical(fact.native_identity)))
    if reader.readable and not facts:
        gaps.append(empty_gap(LANE, unit_id=unit_id))
    return LaneResult(tuple(facts), tuple(gaps), reader.ledger())
