"""Deterministic review-package assembly and membership audits (contract gates 3-6).

Lane A: every accepted lead of every family whose normalized reported severity is in the admitted
list (default critical, high, unknown), and every KEV-listed advisory lead when
``admit_kev`` is set, gets exactly one ``finding_lead`` package, including suppressed and
duplicate leads; each lead records its ``admission_reasons``. Lane B: ranked review units above
the cutoff get ``hunt`` packages whose lead menus list every lead in the unit, partitioned and never
truncated. Lane A leads carry the bounded ``advisory_context``; hunt-menu leads carry the compact
``advisory_summary``; every lead with a CWE carries ``weaknesses`` blocks (CWE id, name,
abstraction) from the run-pinned MITRE catalog or, failing that, the accepted
``reference_intelligence`` facts.

Schema v4 adds accepted code-graph context (docs/architecture/code-graph-precomputation.md section
7.5): ``context`` roles ``entry_point``, ``sink``, ``path``, ``guard`` and ``range``;
``retrieval.graph_families`` naming the graph families accepted (any coverage state but
``unavailable``) for the package scope; ``retrieval.graph_scopes`` naming the CodeQL scope ids of
those facts, which bound the scope-checked graph grant of every cell capability for the package; and ``code_graph`` coverage gaps for the scope's graph
lane. A lead package embeds the ``dataflow_path`` facts correlated ``bridged`` or ``partial`` with
its observation, their sink and entry point, and the sink's ``guard_fact``/``range_fact`` facts. A
hunt package embeds, per unit, ``sink_site`` and ``entry_point`` identities taken round-robin by
class within ``max_context_entries``; the rest are counted in ``omitted_context``. Graph context is
a search aid: each embedded identity is cited and re-resolved like any other.

Packages are canonical JSON. ``package_id`` is the kind plus the SHA-256 of the canonical body
without ``package_id``; arrays sort by stable identity; nothing time- or order-dependent enters a
package. Reassembly from the same accepted inputs is byte-identical. A missing producer is a
named gap; a membership or integrity failure raises :class:`IntegrityError`.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, fields
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.graph.contract import FAMILY_KINDS, GRAPH_INDEX, Family
from appsec_review.indexing.store import ShardSet, shard_key
from appsec_review.retrieval.model import LogicalIdentity
from appsec_review.retrieval.observations import REPORTED_SEVERITIES, SEVERITY_ORDER
from appsec_review.review import advisories as advisory_reference
from appsec_review.review.identity import sha256_hex
from appsec_review.review.lead_families import FAMILIES, FAMILY_RULES, Lead, LeadCollection, collect_leads
from appsec_review.review.models import IntegrityError, Predicate
from appsec_review.review.ranking import DEFAULT_RANK_WEIGHTS, RankWeights
from appsec_review.review.references import CweReference
from appsec_review.review.scope import AcceptedScope, ScopeGap, sorted_gaps
from appsec_review.review.units import (
    RANK_RULE, ContextEntry, RankedUnit, build_units, context_entry, rank_units, select_hunts,
)
from appsec_review.storage import atomic_bytes, file_sha256
from appsec_review.storage.atomic import canonical_json


PACKAGE_SCHEMA = "appsec-review/review-package/4"
ASSEMBLY_RULE = "appsec-review/assemble-review-packages/4"
GRAPH_CONTEXT_RULE = "appsec-review/package-graph-context/1"
GRAPH_PRODUCER = "code_graph"
# Graph fact kind -> package context role (schema v4). call_site and flow_summary are not embedded.
GRAPH_ROLES: Mapping[str, str] = {"entry_point": "entry_point", "sink_site": "sink", "dataflow_path": "path",
                                  "guard_fact": "guard", "range_fact": "range"}
CORRELATED_STATES = frozenset({"bridged", "partial"})
_GRAPH_KINDS = tuple(sorted(kind.value for kind in FAMILY_KINDS.values()))
MAX_WEAKNESSES = 8
MANIFEST_SCHEMA = "appsec-review/review-package-manifest/1"
OBLIGATION_RULE = "appsec-review/package-obligations/1"
SUPPRESSION_STATES = ("suppressed", "possibly_suppressed", "not_suppressed", "unknown")
_P = Predicate
# Deterministic obligation table keyed by lead family; every predicate starts open.
OBLIGATIONS: Mapping[str, tuple[Predicate, ...]] = {
    "source_sast": (_P.AFFECTED_CONSTRUCT, _P.ATTACKER_INPUT_CONTROL, _P.SOURCE_TO_SINK_REACHABILITY,
                    _P.MISSING_OR_INEFFECTIVE_GUARD, _P.SECURITY_IMPACT),
    "codeql": (_P.AFFECTED_CONSTRUCT, _P.ATTACKER_INPUT_CONTROL, _P.SOURCE_TO_SINK_REACHABILITY,
               _P.MISSING_OR_INEFFECTIVE_GUARD, _P.SECURITY_IMPACT),
    "dependency_advisory": (_P.AFFECTED_CONSTRUCT, _P.SOURCE_TO_SINK_REACHABILITY, _P.CONFIGURATION_ENABLES,
                            _P.SECURITY_IMPACT),
    "artifact_scanner": (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT),
    "post_build_hardening": (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT),
    "ci_rule": (_P.AFFECTED_CONSTRUCT, _P.ATTACKER_INPUT_CONTROL, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT),
    "owasp_control": (_P.AFFECTED_CONSTRUCT, _P.MISSING_OR_INEFFECTIVE_GUARD, _P.SECURITY_IMPACT),
    "hunt": tuple(Predicate),
}


@dataclass(frozen=True, slots=True)
class PackageSettings:
    admit_severities: tuple[str, ...] = ("critical", "high", "unknown")
    admit_kev: bool = True
    hunt_max_units: int = 8
    hunt_menu_partition_size: int = 25
    unit_max_files: int = 200
    max_context_entries: int = 64
    max_package_bytes: int = 64 * 1024
    max_page_size: int = 20
    max_pages: int = 5
    max_depth: int = 4
    rank_weights: RankWeights = DEFAULT_RANK_WEIGHTS   # lane B rank weights (``settings.ranking``)

    def __post_init__(self) -> None:
        if not isinstance(self.rank_weights, RankWeights):
            raise ValueError("rank_weights must be RankWeights")
        admitted = tuple(self.admit_severities)
        if not admitted or len(set(admitted)) != len(admitted) or any(
                item not in REPORTED_SEVERITIES for item in admitted):
            raise ValueError("admit_severities must be distinct normalized reported severities")
        object.__setattr__(self, "admit_severities", tuple(sorted(admitted, key=SEVERITY_ORDER.__getitem__)))
        if not isinstance(self.admit_kev, bool):
            raise ValueError("admit_kev must be a Boolean")
        for name in ("hunt_menu_partition_size", "unit_max_files", "max_context_entries", "max_package_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.hunt_max_units, bool) or not isinstance(self.hunt_max_units, int) or self.hunt_max_units < 0:
            raise ValueError("hunt_max_units must be a non-negative integer")
        for name, bound in (("max_page_size", 100), ("max_pages", 100), ("max_depth", 8)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= bound:
                raise ValueError(f"{name} must be between 1 and {bound}")

    @classmethod
    def from_review_settings(cls, settings: Any) -> "PackageSettings":
        """Package settings from the central ``InferenceSecurityReviewSettings`` (the job's only source).

        Admission is ``lanes.lead_admission`` plus ``lanes.lead_admission_kev``, the hunt cutoff
        ``lanes.hunt_max_units``, the assembly bounds ``packages.*``, and the lane B rank weights
        ``ranking``. The dataclass defaults exist for library and test use only.
        """
        bounds = settings.packages
        return cls(admit_severities=tuple(settings.lanes.lead_admission),
                   admit_kev=settings.lanes.lead_admission_kev,
                   hunt_max_units=settings.lanes.hunt_max_units, rank_weights=settings.ranking,
                   **{item.name: getattr(bounds, item.name) for item in fields(cls)
                      if item.name not in {"admit_severities", "admit_kev", "hunt_max_units", "rank_weights"}})

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "PackageSettings":
        value = dict(value or {})
        known = {item.name for item in fields(cls)}
        unknown = sorted(set(value) - known)
        if unknown:
            raise ValueError(f"unknown package settings: {unknown}")
        if "admit_severities" in value:
            value["admit_severities"] = tuple(value["admit_severities"])
        if "rank_weights" in value and not isinstance(value["rank_weights"], RankWeights):
            value["rank_weights"] = RankWeights.from_mapping(value["rank_weights"], "rank_weights")
        return cls(**value)

    def record(self) -> dict[str, Any]:
        return {**asdict(self), "admit_severities": list(self.admit_severities)}


@dataclass(frozen=True, slots=True)
class Package:
    package_id: str
    kind: str
    lane: str
    lead_family: str | None
    partition_key: str
    lead_ids: tuple[str, ...]
    unit_key: str | None
    body: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def document(self) -> dict[str, Any]:
        return json.loads(self.body)

    def entry(self) -> dict[str, Any]:
        return {"package_id": self.package_id, "kind": self.kind, "lane": self.lane,
                "lead_family": self.lead_family, "partition_key": self.partition_key, "unit_key": self.unit_key,
                "lead_count": len(self.lead_ids), "sha256": self.sha256, "bytes": len(self.body)}


@dataclass(frozen=True, slots=True)
class Assembly:
    packages: tuple[Package, ...]
    manifest: Mapping[str, Any]
    gaps: tuple[ScopeGap, ...]

    @property
    def manifest_bytes(self) -> bytes:
        return canonical_json(self.manifest)


def admission_reasons(lead: Lead, settings: PackageSettings) -> list[str]:
    """Why lane A admits ``lead``: its reported severity, a KEV listing, both, or nothing."""
    reasons = ["reported_severity"] if lead.reported_severity in settings.admit_severities else []
    if settings.admit_kev and lead.kev_listed is True:
        reasons.append("kev_listed")
    return reasons


def lead_record(lead: Lead, component_id: str, build_unit_id: str | None, *,
                weaknesses: list[dict[str, Any]] | None = None,
                admission: list[str] | None = None) -> dict[str, Any]:
    """One lead-menu entry; ``admission`` is given only for lane A, which also gets the full context."""
    duplicate = lead.duplicate_of
    if duplicate is not None:
        LogicalIdentity.parse(duplicate)
    lane_a: dict[str, Any] = {} if admission is None else {"admission_reasons": list(admission),
                                                            "advisory_context": lead.advisory}
    return {**lane_a, "weaknesses": list(weaknesses or ()),
            "advisory_summary": advisory_reference.summary_of(lead.advisory),
        "observation_id": lead.observation_id, "lead_family": lead.family, "scanner": lead.scanner,
        "rule_id": lead.rule_id, "message": lead.message, "rule_cwe": list(lead.rule_cwe),
        "native_severity": lead.native_severity, "reported_severity": lead.reported_severity,
        "severity_rule": lead.severity_rule, "severity_basis": lead.severity_basis,
        "component_id": component_id, "build_unit_id": build_unit_id,
        "suppression_status": lead.suppression_status if lead.suppression_status in SUPPRESSION_STATES else "unknown",
        "duplicate_of": duplicate, "location_exact": lead.location_exact, "flow_ids": list(lead.flow_ids),
    }


def _evidence(lead: Lead) -> dict[str, Any]:
    if lead.location_exact and lead.path is not None:
        resolution = "source_line"
    elif any(role == "artifact" for _identity, role in lead.related):
        resolution = "run_artifact"
    else:
        resolution = "unresolved"
    return {"entity_id": lead.observation_id, "relation": "nominates", "shard_id": lead.shard_label,
            "shard_sha256": lead.shard_sha256, "resolution": resolution}


# Code graph ----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Fact:
    identity: str
    kind: str
    path: str | None
    klass: str | None                  # sink_class or source_class
    sink: str | None                   # the sink_site a path, guard or range fact names
    entry: str | None                  # the entry_point a path names
    shard_sha256: str


@dataclass(frozen=True, slots=True)
class _GraphShard:
    label: str
    sha256: str
    families: frozenset[str]
    build_unit_ids: frozenset[str]
    paths: frozenset[str]
    scope_ids: frozenset[str]          # CodeQL scope ids of the shard (producer and fact payloads)
    state: str                         # complete | partial | unavailable
    reason: str | None


def _nested(value: Any, *keys: str) -> Any:
    for key in keys:
        value = value.get(key) if isinstance(value, Mapping) else None
    return value


def _identity_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return LogicalIdentity.parse(value).value
    except ValueError:
        return None


def _shard_state(rows: list[Mapping[str, Any]]) -> tuple[str, str | None]:
    statuses = {str(row["status"]) for row in rows}
    reasons = sorted({str(row["gap"]) for row in rows if row["gap"]})
    reason = "; ".join(reasons)[:500] or None
    if not statuses or statuses == {"unavailable"}:
        return "unavailable", reason or "graph shard publishes no available coverage"
    if statuses == {"complete"}:
        return "complete", None
    return "partial", reason or "graph shard coverage is partial"


class GraphContext:
    """Accepted ``graph`` facts indexed for package assembly; pure reads of verified shards.

    A graph shard applies to a package scope when it names the scope's build unit (shard producer
    ``build_unit_id`` or a fact's ``scope.build_unit_id``) or holds a fact located in one of the
    scope's paths. A family is accepted for the scope when an applying shard covers it in any
    state but ``unavailable``. Absence is a named ``code_graph`` gap, never an empty clean result.
    """

    def __init__(self, scope: AcceptedScope):
        shards = scope.select(lambda shard: shard["name"] == GRAPH_INDEX)
        self.available = bool(shards)
        self.shards: list[_GraphShard] = []
        self.facts: dict[str, _Fact] = {}
        self.correlated: dict[str, set[str]] = defaultdict(set)
        store = scope.store
        family_names = {item.value for item in Family}
        for shard in sorted(shards, key=shard_key):
            sha = scope.shard_sha256(shard)
            producer = shard.get("producer") or {}
            families: set[str] = set()
            units: set[str] = set()
            paths: set[str] = set()
            scope_ids: set[str] = set()
            if isinstance(producer.get("scope_id"), str) and producer["scope_id"]:
                scope_ids.add(str(producer["scope_id"]))
            if producer.get("family") in family_names:
                families.add(str(producer["family"]))
            if isinstance(producer.get("build_unit_id"), str) and producer["build_unit_id"]:
                units.add(str(producer["build_unit_id"]))
            for row in store.entities((shard,), kinds=_GRAPH_KINDS):
                payload = row["payload"] if isinstance(row["payload"], Mapping) else {}
                result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
                kind = str(row["kind"])
                path = (row.get("location") or {}).get("path")
                families.add(kind)
                unit = _nested(payload, "scope", "build_unit_id")
                if isinstance(unit, str) and unit:
                    units.add(unit)
                scope_id = _nested(payload, "scope", "scope_id")
                if isinstance(scope_id, str) and scope_id:
                    scope_ids.add(scope_id)
                if path:
                    paths.add(str(path))
                klass = (result.get("sink_class") if kind == "sink_site" else
                         result.get("source_class") if kind == "entry_point" else None)
                self.facts[str(row["identity"])] = _Fact(
                    str(row["identity"]), kind, str(path) if path else None,
                    str(klass) if isinstance(klass, str) and klass else None,
                    _identity_or_none(_nested(result, "sink", "sink_site")),
                    _identity_or_none(_nested(result, "source", "entry_point")), sha)
            state, reason = _shard_state(store.coverage((shard,)))
            self.shards.append(_GraphShard(f"{shard['name']}/{shard.get('shard_id', 'default')}", sha,
                                           frozenset(families), frozenset(units), frozenset(paths),
                                           frozenset(scope_ids), state, reason))
        for relation in store.relations(shards, kinds=("DERIVED_FROM",)):
            source = self.facts.get(str(relation["source_id"]))
            if (source is not None and source.kind == "dataflow_path"
                    and _nested(relation["payload"], "state") in CORRELATED_STATES):
                self.correlated[str(relation["target_id"])].add(source.identity)

    def applying(self, build_unit_id: str | None, paths: Iterable[str]) -> list[_GraphShard]:
        members = set(paths)
        return [item for item in self.shards
                if (build_unit_id is not None and build_unit_id in item.build_unit_ids) or item.paths & members]

    def scopes(self, build_unit_id: str | None, paths: Iterable[str]) -> list[str]:
        """CodeQL scope ids whose accepted (not ``unavailable``) graph facts apply to a package scope.

        These become ``retrieval.graph_scopes``: a review cell may receive and cite graph rows whose
        own ``scope.scope_id`` is listed, and nothing from any other scope.
        """
        return sorted({scope_id for item in self.applying(build_unit_id, paths) if item.state != "unavailable"
                       for scope_id in item.scope_ids})

    def families(self, build_unit_id: str | None, paths: Iterable[str], subject: str
                 ) -> tuple[list[str], list[str], list[ScopeGap]]:
        """Accepted families, applying shard hashes and ``code_graph`` gaps for one package scope."""
        if not self.available:
            return [], [], [ScopeGap(GRAPH_PRODUCER, subject, "missing",
                                     "no accepted graph index in the accepted index set; graph facts, sink_up and "
                                     "entry_down are unavailable for this scope, not clean")]
        applying = self.applying(build_unit_id, paths)
        states: dict[str, set[str]] = defaultdict(set)
        reasons: dict[str, set[str]] = defaultdict(set)
        for item in applying:
            for family in item.families:
                states[family].add(item.state)
                if item.reason:
                    reasons[family].add(item.reason)
        accepted = sorted(family for family, values in states.items() if values != {"unavailable"})
        gaps: list[ScopeGap] = []
        partial = sorted(family for family in accepted if states[family] != {"complete"})
        absent = sorted(family.value for family in Family if family.value not in accepted)
        if partial:
            detail = "; ".join(sorted({reason for family in partial for reason in reasons[family]}))
            gaps.append(ScopeGap(GRAPH_PRODUCER, subject, "partial",
                                 f"graph families partial for this scope: {', '.join(partial)}"
                                 + (f" ({detail})" if detail else "")))
        if absent:
            gaps.append(ScopeGap(GRAPH_PRODUCER, subject, "unavailable",
                                 f"graph families unavailable for this scope: {', '.join(absent)}; "
                                 "absence of a graph fact is a gap, never evidence"))
        return accepted, sorted({item.sha256 for item in applying}), gaps

    def lead_context(self, observation_id: str) -> list[ContextEntry]:
        """Correlated paths of one observation with their sink, entry point, guards and ranges."""
        entries: list[ContextEntry] = []
        sinks: set[str] = set()
        for identity in sorted(self.correlated.get(observation_id, ())):
            path = self.facts[identity]
            entries.append(context_entry(identity, GRAPH_ROLES["dataflow_path"], path.shard_sha256))
            for related in (path.sink, path.entry):
                fact = self.facts.get(related) if related else None
                if fact is not None and fact.kind in GRAPH_ROLES:
                    entries.append(context_entry(fact.identity, GRAPH_ROLES[fact.kind], fact.shard_sha256))
            if path.sink:
                sinks.add(path.sink)
        for fact in sorted(self.facts.values(), key=lambda item: item.identity):
            if fact.kind in {"guard_fact", "range_fact"} and fact.sink in sinks:
                entries.append(context_entry(fact.identity, GRAPH_ROLES[fact.kind], fact.shard_sha256))
        return entries

    def unit_context(self, paths: Iterable[str], budget: int) -> tuple[list[ContextEntry], int]:
        """Sink and entry-point identities in ``paths``, round-robin by (role, class), bounded."""
        members = set(paths)
        buckets: dict[tuple[str, str], list[_Fact]] = defaultdict(list)
        for fact in self.facts.values():
            if fact.kind in {"sink_site", "entry_point"} and fact.path in members:
                buckets[(GRAPH_ROLES[fact.kind], fact.klass or "unclassified")].append(fact)
        queues = [sorted(buckets[key], key=lambda item: item.identity) for key in sorted(buckets)]
        total = sum(len(queue) for queue in queues)
        budget = max(0, budget)
        chosen: list[ContextEntry] = []
        depth = 0
        while len(chosen) < budget and any(depth < len(queue) for queue in queues):
            for queue in queues:
                if depth < len(queue) and len(chosen) < budget:
                    fact = queue[depth]
                    chosen.append(context_entry(fact.identity, GRAPH_ROLES[fact.kind], fact.shard_sha256))
            depth += 1
        return chosen, total - len(chosen)


class _Assembler:
    def __init__(self, scope: AcceptedScope, settings: PackageSettings, collection: LeadCollection,
                 cwe_reference: CweReference | None = None):
        self.scope = scope
        self.settings = settings
        self.collection = collection
        self.correlation_hashes = tuple(sorted(str(item["sha256"]) for item in collection.correlation_shards))
        self.extra_gaps: list[ScopeGap] = []
        self.cwe_reference = cwe_reference
        self.reference_weaknesses = _reference_weaknesses(scope)
        self.graph = GraphContext(scope)

    def weaknesses(self, lead: Lead) -> list[dict[str, Any]]:
        """Weakness blocks for the lead's rule CWEs and its advisories' NVD CWEs (bounded)."""
        origins: dict[str, str] = {cwe: "rule" for cwe in lead.rule_cwe}
        for cwe in advisory_reference.nvd_cwes(lead.advisory):
            origins.setdefault(cwe, "nvd")
        blocks = []
        for cwe in sorted(origins, key=lambda value: int(value[4:]))[:MAX_WEAKNESSES]:
            entry = self.cwe_reference.lookup(cwe) if self.cwe_reference is not None else None
            if entry is not None:
                blocks.append({"cwe_id": cwe, "name": entry.name, "abstraction": entry.abstraction,
                               "source": "mitre_catalog", "origin": origins[cwe]})
            elif cwe in self.reference_weaknesses:
                name, abstraction = self.reference_weaknesses[cwe]
                blocks.append({"cwe_id": cwe, "name": name, "abstraction": abstraction,
                               "source": "reference_intelligence", "origin": origins[cwe]})
            else:
                blocks.append({"cwe_id": cwe, "name": None, "abstraction": None, "source": "unresolved",
                               "origin": origins[cwe]})
        return blocks

    def _locate(self, lead: Lead) -> tuple[str, str | None, Any, Any]:
        component = self.scope.component_for(lead.path)
        unit = self.scope.build_unit_for(lead.path)
        return (component.component_id if component else lead.component_hint or "unassigned",
                unit.build_unit_id if unit else None, component, unit)

    def _cap(self, context: Iterable[ContextEntry], subject: str, producer: str
             ) -> tuple[list[ContextEntry], int, list[ScopeGap]]:
        unique = {(item.role, item.id): item for item in context}
        ordered = [unique[key] for key in sorted(unique)]
        bound = self.settings.max_context_entries
        if len(ordered) <= bound:
            return ordered, 0, []
        omitted = len(ordered) - bound
        return ordered[:bound], omitted, [ScopeGap(producer, subject, "truncated",
                                                   f"{omitted} context entr{'y' if omitted == 1 else 'ies'} "
                                                   f"exceeded max_context_entries={bound}")]

    def _build(self, *, kind: str, lead_family: str | None, scope_record: Mapping[str, Any],
               partition: tuple[int, int], rank: Mapping[str, Any] | None, menu: list[tuple[Lead, str, str | None]],
               context: list[ContextEntry], obligations: Iterable[Predicate], gaps: Iterable[ScopeGap],
               truncation: Mapping[str, Any], graph_families: Iterable[str] = (),
               graph_shards: Iterable[str] = (), graph_scopes: Iterable[str] = ()) -> tuple[str, bytes]:
        leads = sorted(menu, key=lambda item: (SEVERITY_ORDER[item[0].reported_severity], item[0].observation_id))
        lead_ids = sorted(item[0].observation_id for item in leads)
        entities = sorted({*lead_ids, *scope_record["source_ids"], *scope_record["artifact_ids"],
                           *(item.id for item in context)})
        shard_hashes = sorted({*(item[0].shard_sha256 for item in leads),
                               *(item.shard_sha256 for item in context if item.shard_sha256), *graph_shards,
                               *(self.correlation_hashes if any(item[0].family in {"source_sast", "codeql"}
                                                                for item in leads) else ())})
        retrieval = {"indexes": list(self.scope.index_names), "query_sets": list(self.scope.query_sets),
                     "graph_families": sorted(set(graph_families)), "graph_scopes": sorted(set(graph_scopes)),
                     "entity_ids": entities, "max_page_size": self.settings.max_page_size,
                     "max_pages": self.settings.max_pages, "max_depth": self.settings.max_depth}
        fingerprint = sha256_hex({
            "manifest_sha256": self.scope.manifest_sha256, "scope": dict(scope_record), "shards": shard_hashes,
            "lead_ids": lead_ids, "rules": {"assembly": ASSEMBLY_RULE, "obligations": OBLIGATION_RULE,
                                            "rank": RANK_RULE, "families": FAMILY_RULES,
                                            "advisory_context": advisory_reference.CONTEXT_RULE,
                                            "graph_context": GRAPH_CONTEXT_RULE},
            "cwe_reference": self.cwe_reference.record() if self.cwe_reference is not None else None,
            "caps": self.settings.record()})
        body = {
            "schema": PACKAGE_SCHEMA, "kind": kind, "lane": "lead" if kind == "finding_lead" else "hunt",
            "lead_family": lead_family, "run_id": self.scope.run_id, "manifest_sha256": self.scope.manifest_sha256,
            "target_snapshot": self.scope.target_snapshot, "input_fingerprint": fingerprint,
            "assembly_rule": ASSEMBLY_RULE, "scope": dict(scope_record),
            "partition": {"number": partition[0], "count": partition[1]}, "rank": rank,
            "persona": None, "stack_profile": None,
            "lead_menu": [lead_record(*item, weaknesses=self.weaknesses(item[0]),
                                      admission=admission_reasons(item[0], self.settings)
                                      if kind == "finding_lead" else None) for item in leads],
            "evidence": sorted((_evidence(item[0]) for item in leads), key=lambda value: value["entity_id"]),
            "context": [item.record() for item in context],
            "proof_obligations": sorted(item.value for item in obligations),
            "retrieval": retrieval, "coverage_gaps": [gap.record() for gap in sorted_gaps(gaps)],
            "truncation": dict(truncation),
        }
        package_id = f"{kind}-{sha256_hex(body)}"
        return package_id, canonical_json({**body, "package_id": package_id})

    # Lane A ---------------------------------------------------------------------------------------
    def finding_lead(self, lead: Lead) -> Package:
        component_id, unit_id, component, unit = self._locate(lead)
        source = self.scope.source_for(lead.path)
        context: list[ContextEntry] = []
        sources = {source.identity} if source else set()
        artifacts: set[str] = set()
        for identity, role in lead.related:
            if role == "source":
                sources.add(identity)
            elif role == "artifact":
                artifacts.add(identity)
            else:
                context.append(context_entry(identity, role))
        if component is not None:
            context.append(context_entry(component.identity, "component"))
        if unit is not None:
            context.append(context_entry(unit.identity, "build_unit"))
        if lead.duplicate_of:
            context.append(context_entry(lead.duplicate_of, "duplicate_of"))
        context.extend(context_entry(identity, "flow") for identity in lead.flow_ids)
        context.extend(self.graph.lead_context(lead.observation_id))
        partition_key = f"lead/{lead.observation_id}"
        families, graph_shards, graph_gaps = self.graph.families(unit_id, (lead.path,) if lead.path else (),
                                                                 partition_key)
        capped, omitted, gaps = self._cap(context, partition_key, lead.family)
        gaps.extend(graph_gaps)
        gaps.extend(gap for gap in self.collection.gaps if gap.producer == lead.family)
        if not lead.location_exact:
            gaps.append(ScopeGap(lead.family, partition_key, "ambiguous",
                                 "lead location is unresolved or ambiguous; no source line is cited"))
        scope_record = {"component_id": component_id, "trust_boundary_id": None, "build_unit_id": unit_id,
                        "partition_key": partition_key, "source_ids": sorted(sources), "artifact_ids": sorted(artifacts)}
        while True:
            package_id, body = self._build(
                kind="finding_lead", lead_family=lead.family, scope_record=scope_record, partition=(0, 1), rank=None,
                menu=[(lead, component_id, unit_id)], context=capped, obligations=OBLIGATIONS[lead.family],
                gaps=gaps, truncation={"omitted_leads": 0, "omitted_context": omitted, "next_partition": None},
                graph_families=families, graph_shards=graph_shards,
                graph_scopes=self.graph.scopes(unit_id, (lead.path,) if lead.path else ()))
            if len(body) <= self.settings.max_package_bytes:
                break
            if not capped:
                raise IntegrityError(f"finding-lead package for {lead.observation_id} exceeds max_package_bytes and "
                                     "cannot be partitioned; the membership gate is blocked")
            capped = capped[:-1]
            omitted += 1
            gaps = [gap for gap in gaps if gap.state != "truncated"] + [ScopeGap(
                lead.family, partition_key, "truncated",
                f"{omitted} context entries omitted to respect max_package_bytes")]
        self.extra_gaps.extend(gap for gap in gaps if gap.state == "truncated")
        return Package(package_id, "finding_lead", "lead", lead.family, partition_key, (lead.observation_id,),
                       None, body)

    # Lane B ---------------------------------------------------------------------------------------
    def hunts(self, ranked: RankedUnit) -> list[Package]:
        unit = ranked.unit
        menu = [(lead, *self._locate(lead)[:2]) for lead in unit.leads]
        menu.sort(key=lambda item: (SEVERITY_ORDER[item[0].reported_severity], item[0].observation_id))
        bound = self.settings.max_context_entries
        budget = bound - len({(item.role, item.id) for item in unit.context})
        graph_context, graph_omitted = self.graph.unit_context(unit.paths, budget)
        context, omitted, gaps = self._cap((*unit.context, *graph_context), unit.key, "lane_b_hunt")
        if graph_omitted:
            omitted += graph_omitted
            gaps.append(ScopeGap(GRAPH_PRODUCER, unit.key, "truncated",
                                 f"{graph_omitted} graph context entr{'y' if graph_omitted == 1 else 'ies'} "
                                 f"exceeded max_context_entries={bound}"))
        families, graph_shards, graph_gaps = self.graph.families(unit.build_unit_id, unit.paths, unit.key)
        graph_scopes = self.graph.scopes(unit.build_unit_id, unit.paths)
        missing = [gap for gap in (*self.scope.gaps, *self.collection.gaps) if gap.state == "missing"]
        scope_record = {"component_id": unit.component_id, "trust_boundary_id": unit.trust_boundary_id,
                        "build_unit_id": unit.build_unit_id, "source_ids": list(unit.source_ids),
                        "artifact_ids": sorted({identity for lead in unit.leads for identity, role in lead.related
                                                if role == "artifact"})}
        rank = ranked.rank_record()

        def render(chunk: list, number: int, count: int) -> tuple[str, bytes]:
            key = f"{unit.key}#{number:05d}"
            following = f"{unit.key}#{number + 1:05d}" if number + 1 < count else None
            return self._build(
                kind="hunt", lead_family=None, scope_record={**scope_record, "partition_key": key},
                partition=(number, count), rank=rank, menu=chunk, context=context, obligations=OBLIGATIONS["hunt"],
                gaps=[*gaps, *graph_gaps, *missing], truncation={"omitted_leads": 0, "omitted_context": omitted,
                                                                 "next_partition": following},
                graph_families=families, graph_shards=graph_shards, graph_scopes=graph_scopes)

        def split(chunk: list) -> list[list]:
            _identity, body = render(chunk, 99_998, 99_999)  # widest numbering bounds the final size
            if len(body) <= self.settings.max_package_bytes:
                return [chunk]
            if len(chunk) <= 1:
                raise IntegrityError(f"hunt partition of {unit.key} exceeds max_package_bytes with a single lead; "
                                     "the membership gate is blocked")
            middle = len(chunk) // 2
            return split(chunk[:middle]) + split(chunk[middle:])

        size = self.settings.hunt_menu_partition_size
        chunks = [chunk for offset in range(0, max(1, len(menu)), size)
                  for chunk in split(menu[offset:offset + size])]
        self.extra_gaps.extend(gaps)
        packages = []
        for number, chunk in enumerate(chunks):
            package_id, body = render(chunk, number, len(chunks))
            packages.append(Package(package_id, "hunt", "hunt", None, f"{unit.key}#{number:05d}",
                                    tuple(sorted(item[0].observation_id for item in chunk)), unit.key, body))
        return packages


def audit_membership(collection: LeadCollection, packages: Iterable[Package],
                     admit: Iterable[str], admit_kev: bool = False) -> dict[str, Any]:
    """Gate 5 for lane A: E ⊆ F per family and severity, exactly once, with no invented lead.

    ``E`` holds every lead whose reported severity is admitted and, with ``admit_kev``, every
    KEV-listed lead whatever its reported severity.
    """
    admitted = set(admit)
    expected = {lead.observation_id: lead for lead in collection.leads
                if lead.reported_severity in admitted or (admit_kev and lead.kev_listed is True)}
    seen: Counter[str] = Counter()
    for package in packages:
        if package.kind == "finding_lead":
            seen.update(package.lead_ids)
    missing = sorted(set(expected) - set(seen))
    repeated = sorted(key for key, count in seen.items() if count > 1)
    invented = sorted(set(seen) - set(expected))
    if missing or repeated or invented:
        raise IntegrityError(f"lane A membership audit failed: missing={missing[:5]} repeated={repeated[:5]} "
                             f"invented={invented[:5]}")
    by_cell: dict[str, dict[str, dict[str, int]]] = {}
    severities = admitted | {lead.reported_severity for lead in expected.values()}
    for family in FAMILIES:
        by_cell[family] = {}
        for severity in sorted(severities, key=SEVERITY_ORDER.__getitem__):
            members = [key for key, lead in expected.items() if lead.family == family and lead.reported_severity == severity]
            packaged = sum(seen[key] for key in members)
            if packaged != len(members):
                raise IntegrityError(f"lane A membership audit failed for {family}/{severity}")
            by_cell[family][severity] = len(members)
    return {"status": "passed", "expected": len(expected), "packaged": sum(seen.values()), "by_family": by_cell,
            "suppressed": sum(1 for lead in expected.values() if lead.suppression_status == "suppressed"),
            "duplicates": sum(1 for lead in expected.values() if lead.duplicate_of),
            "kev_admitted": sum(1 for lead in expected.values() if lead.reported_severity not in admitted)}


def audit_hunts(hunted: Iterable[RankedUnit], packages: Iterable[Package]) -> dict[str, Any]:
    """Every lead of a hunted unit appears in exactly one of its menu partitions; none is invented."""
    menus: dict[str, Counter[str]] = defaultdict(Counter)
    for package in packages:
        if package.kind == "hunt":
            menus[str(package.unit_key)].update(package.lead_ids)
    listed = 0
    for item in hunted:
        expected = set(item.unit.lead_ids)
        found = menus.pop(item.unit.key, Counter())
        if set(found) != expected or any(count != 1 for count in found.values()):
            raise IntegrityError(f"lane B hunt menu membership failed for {item.unit.key}")
        listed += len(expected)
    if menus:
        raise IntegrityError(f"hunt packages exist for units that were not selected: {sorted(menus)[:5]}")
    return {"status": "passed", "listed_leads": listed}


def assemble_packages(scope: AcceptedScope, settings: PackageSettings | None = None, *,
                      collection: LeadCollection | None = None,
                      cwe_reference: CweReference | None = None) -> Assembly:
    """Assemble both lanes and the package manifest; raises on any membership or integrity failure.

    ``cwe_reference`` is the run-pinned MITRE CWE catalog (``review.references``); without it,
    weakness names come from the accepted ``reference_intelligence`` facts or stay unresolved.
    """
    settings = settings or PackageSettings()
    collection = collection if collection is not None else collect_leads(scope)
    collection = LeadCollection(tuple(sorted(collection.leads, key=lambda lead: lead.observation_id)),
                                collection.gaps, collection.available, collection.correlation_audit,
                                collection.correlation_shards, collection.non_lead_counts)
    assembler = _Assembler(scope, settings, collection, cwe_reference)
    admitted = [lead for lead in collection.leads if admission_reasons(lead, settings)]
    packages = [assembler.finding_lead(lead) for lead in admitted]
    lane_a = audit_membership(collection, packages, settings.admit_severities, settings.admit_kev)

    units = build_units(scope, collection, unit_max_files=settings.unit_max_files, weights=settings.rank_weights)
    ranked = rank_units(units)
    hunted, cutoff_gaps = select_hunts(ranked, settings.hunt_max_units)
    for item in hunted:
        packages.extend(assembler.hunts(item))
    lane_b = audit_hunts(hunted, packages)
    packages.sort(key=lambda package: package.package_id)
    if len({package.package_id for package in packages}) != len(packages):
        raise IntegrityError("package identity collision")
    scope.verify()

    # A missing graph index is already the scope's ``code_graph`` producer gap (review/scope.py).
    gaps = sorted_gaps((*scope.gaps, *collection.gaps, *cutoff_gaps, *assembler.extra_gaps))
    hunted_keys = {item.unit.key for item in hunted}
    unit_packages: dict[str, list[str]] = defaultdict(list)
    for package in packages:
        if package.unit_key is not None:
            unit_packages[package.unit_key].append(package.package_id)
    admitted_counts = {family: {severity: sum(1 for lead in admitted if lead.family == family
                                              and lead.reported_severity == severity)
                                for severity in settings.admit_severities} for family in FAMILIES}
    kev_admitted = {family: sum(1 for lead in admitted if lead.family == family
                                and lead.reported_severity not in settings.admit_severities) for family in FAMILIES}
    document: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA, "assembly_rule": ASSEMBLY_RULE, "package_schema": PACKAGE_SCHEMA,
        "run_id": scope.run_id, "manifest_sha256": scope.manifest_sha256, "target_snapshot": scope.target_snapshot,
        "settings": settings.record(), "rules": {"families": dict(FAMILY_RULES), "rank": RANK_RULE,
                                                 "obligations": OBLIGATION_RULE},
        "inputs": ShardSet.identities(scope.shards), "evidence_map_sha256": sha256_hex(scope.evidence_map()),
        "packages": [package.entry() for package in packages],
        "units": [{"unit_key": item.unit.key, **item.rank_record(), "hunted": item.unit.key in hunted_keys,
                   "lead_count": len(item.unit.leads), "package_ids": sorted(unit_packages.get(item.unit.key, ()))}
                  for item in ranked],
        "gaps": [gap.record() for gap in gaps],
        "cwe_reference": cwe_reference.record() if cwe_reference is not None else None,
        "counts": {"leads": collection.counts(), "admitted": admitted_counts, "kev_admitted": kev_admitted,
                   "non_lead_observations": dict(collection.non_lead_counts),
                   "packages": {"finding_lead": sum(1 for item in packages if item.kind == "finding_lead"),
                                "hunt": sum(1 for item in packages if item.kind == "hunt")},
                   "units": {"total": len(ranked), "hunted": len(hunted), "below_cutoff": len(cutoff_gaps)}},
        "audit": {"lane_a": lane_a, "lane_b": lane_b,
                  "families_available": {family: bool(collection.available.get(family)) for family in FAMILIES}},
    }
    document["content_sha256"] = sha256_hex(document)
    return Assembly(tuple(packages), document, gaps)


def _reference_weaknesses(scope: AcceptedScope) -> dict[str, tuple[str | None, str | None]]:
    """CWE id -> (name, abstraction) from accepted ``reference_intelligence`` facts."""
    found: dict[str, tuple[str | None, str | None]] = {}
    for row in scope.store.entities(scope.producer("reference_intelligence").shards, kinds=("precomputed_fact",)):
        result = row["payload"].get("result") or {}
        weakness = result.get("weakness") if isinstance(result.get("weakness"), Mapping) else {}
        cwe = result.get("weakness_id")
        if isinstance(cwe, str) and weakness.get("known"):
            name, abstraction = weakness.get("name"), weakness.get("abstraction")
            found[cwe] = (str(name)[:256] if name else None, str(abstraction)[:64] if abstraction else None)
    return dict(sorted(found.items()))


def publish_packages(assembly: Assembly, out_dir: Path) -> Path:
    """Write package bytes and the manifest under a run-owned directory, then verify them."""
    out_dir = Path(out_dir)
    for package in assembly.packages:
        path = out_dir / "packages" / f"{package.package_id}.json"
        if path.is_file():
            if path.read_bytes() != package.body:
                raise IntegrityError(f"published package differs from its reassembly: {package.package_id}")
            continue
        atomic_bytes(path, package.body)
    manifest_path = out_dir / "package-manifest.json"
    if manifest_path.is_file() and manifest_path.read_bytes() != assembly.manifest_bytes:
        raise IntegrityError("published package manifest differs from its reassembly")
    atomic_bytes(manifest_path, assembly.manifest_bytes)
    verify_package_manifest(manifest_path)
    return manifest_path


def verify_package_manifest(manifest_path: Path) -> dict[str, Any]:
    """Verify the manifest hash and every package's bytes before a consumer reads them."""
    manifest_path = Path(manifest_path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("schema") != MANIFEST_SCHEMA:
        raise IntegrityError("unsupported package manifest schema")
    claimed = document.pop("content_sha256", None)
    if claimed != sha256_hex(document):
        raise IntegrityError("package manifest content hash mismatch")
    document["content_sha256"] = claimed
    for entry in document["packages"]:
        path = manifest_path.parent / "packages" / f"{entry['package_id']}.json"
        if not path.is_file() or file_sha256(path) != entry["sha256"]:
            raise IntegrityError(f"package bytes do not match the manifest: {entry['package_id']}")
        body = json.loads(path.read_text(encoding="utf-8"))
        package_id = body.pop("package_id")
        if package_id != entry["package_id"] or package_id != f"{body['kind']}-{sha256_hex(body)}":
            raise IntegrityError(f"package identity does not match its body: {entry['package_id']}")
    return document
