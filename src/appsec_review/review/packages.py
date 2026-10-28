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

Schema v5 adds lead-level C/C++ context (docs/architecture/svf-alias-producer.md section 7):
``points_to``, ``indirect_call`` and ``memory_object`` entries joining the lead's source line to
accepted ``job_svf_alias_analysis`` records, whatever scanner reported the lead, and ``caller``
entries naming the accepted ``call_site`` facts that reach the lead's enclosing function, to
``caller_depth`` (default 2). Missing, partial and bounded context is a named gap.

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

from appsec_review.graph.contract import FAMILY_KINDS, GRAPH_INDEX, Family, GraphSettings
from appsec_review.graph.settings import run_graph_settings
from appsec_review.review.artifact_context import ArtifactContext
from appsec_review.graph.svf_crosscheck import function_tail
from appsec_review.indexing.store import ShardSet, shard_key
from appsec_review.retrieval.model import LogicalIdentity
from appsec_review.retrieval.observations import REPORTED_SEVERITIES, SEVERITY_ORDER
from appsec_review.review import advisories as advisory_reference
from appsec_review.review.fact_summary import SUMMARY_RULE, summarize_fact
from appsec_review.review.identity import sha256_hex
from appsec_review.review.lead_families import FAMILIES, FAMILY_RULES, Lead, LeadCollection, collect_leads
from appsec_review.review.memory_context import C_FAMILY_SUFFIXES, MEMORY_CONTEXT_RULE, MemoryContext
from appsec_review.review.models import IntegrityError, Predicate
from appsec_review.review.neighborhood import (
    BUILD_RULE, NEIGHBORHOOD_RULE, SECTIONS as NEIGHBORHOOD_SECTIONS, BuildContext, NeighborhoodRow, empty_record,
)
from appsec_review.review.ranking import DEFAULT_RANK_WEIGHTS, RankWeights
from appsec_review.review.references import CweReference
from appsec_review.review.scope import AcceptedScope, ScopeGap, sorted_gaps
from appsec_review.review.units import (
    RANK_RULE, ContextEntry, RankedUnit, build_units, context_entry, rank_units, select_hunts,
)
from appsec_review.storage import atomic_bytes, file_sha256
from appsec_review.storage.atomic import canonical_json


PACKAGE_SCHEMA = "appsec-review/review-package/6"
ASSEMBLY_RULE = "appsec-review/assemble-review-packages/9"
GRAPH_CONTEXT_RULE = "appsec-review/package-graph-context/2"
CALLER_ROLE = "caller"
CALLER_PRODUCER = "code_graph_callers"
GRAPH_PRODUCER = "code_graph"
# Graph fact kind -> package context role (schema v4). call_site and flow_summary are not embedded.
GRAPH_ROLES: Mapping[str, str] = {"entry_point": "entry_point", "sink_site": "sink", "dataflow_path": "path",
                                  "guard_fact": "guard", "range_fact": "range"}
CORRELATED_STATES = frozenset({"bridged", "partial"})
_GRAPH_KINDS = tuple(sorted(kind.value for kind in FAMILY_KINDS.values()))
MAX_WEAKNESSES = 8
MAX_CORROBORATION = 16
MANIFEST_SCHEMA = "appsec-review/review-package-manifest/1"
OBLIGATION_RULE = "appsec-review/package-obligations/2"
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
    "secret": (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT),
    "config_scanner": (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT),
    "hunt": tuple(Predicate),
}


@dataclass(frozen=True, slots=True)
class PackageSettings:
    admit_severities: tuple[str, ...] = ("critical", "high", "unknown")
    admit_kev: bool = True
    exploration_enabled: bool = False
    exploration_reserve: int = 1
    hunt_max_units: int = 8
    hunt_menu_partition_size: int = 25
    unit_max_files: int = 200
    max_context_entries: int = 64
    max_package_bytes: int = 64 * 1024
    max_page_size: int = 20
    max_pages: int = 5
    max_depth: int = 4
    max_memory_context_entries: int = 24
    max_callers: int = 16
    caller_depth: int = 2
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
        if not isinstance(self.exploration_enabled, bool):
            raise ValueError("exploration_enabled must be a Boolean")
        if type(self.exploration_reserve) is not int or self.exploration_reserve < 1:
            raise ValueError("exploration_reserve must be a positive integer")
        for name in ("hunt_menu_partition_size", "unit_max_files", "max_context_entries", "max_package_bytes",
                     "max_memory_context_entries", "max_callers"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.hunt_max_units, bool) or not isinstance(self.hunt_max_units, int) or self.hunt_max_units < 0:
            raise ValueError("hunt_max_units must be a non-negative integer")
        for name, bound in (("max_page_size", 100), ("max_pages", 100), ("max_depth", 8), ("caller_depth", 4)):
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
        package_budget = settings.budgets.budget_team_packages
        exploration_reserve = settings.lanes.exploration_reserve
        if package_budget != "all":
            exploration_reserve = min(exploration_reserve, package_budget)
        return cls(admit_severities=tuple(settings.lanes.lead_admission),
                   admit_kev=settings.lanes.lead_admission_kev,
                   exploration_enabled=settings.lanes.exploration_enabled,
                   exploration_reserve=exploration_reserve,
                   hunt_max_units=settings.lanes.hunt_max_units, rank_weights=settings.ranking,
                   **{item.name: getattr(bounds, item.name) for item in fields(cls)
                      if item.name not in {"admit_severities", "admit_kev", "exploration_enabled", "exploration_reserve",
                                           "hunt_max_units", "rank_weights"}})

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
    """Why lane A admits ``lead``: reported/assessed severity, a KEV listing, or nothing."""
    reasons = []
    if lead.effective_severity in settings.admit_severities:
        reasons.append("reported_severity" if lead.effective_from == "reported" else "assessed_severity")
    if settings.admit_kev and lead.kev_listed is True:
        reasons.append("kev_listed")
    if not reasons and settings.exploration_enabled and lead.effective_severity in {"medium", "low"}:
        reasons.append("exploration_reserve")
    return reasons


def admitted_leads(collection: LeadCollection, settings: PackageSettings) -> list[Lead]:
    urgent = [lead for lead in collection.leads
              if admission_reasons(lead, settings) and admission_reasons(lead, settings) != ["exploration_reserve"]]
    exploratory = sorted((lead for lead in collection.leads
                          if admission_reasons(lead, settings) == ["exploration_reserve"]),
                         key=lambda lead: (SEVERITY_ORDER[lead.effective_severity], lead.observation_id))
    return urgent + exploratory[:settings.exploration_reserve]


def lead_record(lead: Lead, component_id: str, build_unit_id: str | None, *,
                weaknesses: list[dict[str, Any]] | None = None,
                admission: list[str] | None = None) -> dict[str, Any]:
    """One lead-menu entry; ``admission`` is given only for lane A, which also gets the full context."""
    duplicate = lead.duplicate_of
    if duplicate is not None:
        LogicalIdentity.parse(duplicate)
    lane_a: dict[str, Any] = {} if admission is None else {"admission_reasons": list(admission),
                                                            "advisory_context": lead.advisory}
    return {**lane_a, **({"control_assessment": dict(lead.control_assessment)}
                        if lead.control_assessment is not None else {}),
        "weaknesses": list(weaknesses or ()),
            "advisory_summary": advisory_reference.summary_of(lead.advisory),
        "observation_id": lead.observation_id, "lead_family": lead.family, "scanner": lead.scanner,
        "rule_id": lead.rule_id, "message": lead.message, "rule_cwe": list(lead.rule_cwe),
        "native_severity": lead.native_severity, "reported_severity": lead.reported_severity,
        "severity_rule": lead.severity_rule, "severity_basis": lead.severity_basis,
        "severity_record": lead.severity_record(),
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
    line: int | None = None
    function: str | None = None        # the enclosing function symbol a sink_site or entry_point names
    summary: str = ""                  # fact-summary/1


@dataclass(frozen=True, slots=True)
class _Call:
    identity: str
    caller_symbol: str | None
    caller_name: str                   # unqualified caller name (function_tail of its display)
    callee_symbol: str | None
    callee_name: str
    path: str | None
    line: int | None
    shard_sha256: str
    summary: str = ""


@dataclass(frozen=True, slots=True)
class _Symbol:
    identity: str
    name: str
    path: str
    line: int
    file_sha256: str | None
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
        self.calls: list[_Call] = []
        self.symbols: dict[str, _Symbol] = {}
        self.symbols_by_path: dict[str, list[_Symbol]] = defaultdict(list)
        # (path, line) -> enclosing functions named by sink_site and call_site facts on that line.
        self.enclosing: dict[tuple[str, int], set[tuple[str | None, str]]] = defaultdict(set)
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
            for row in store.entities((shard,), kinds=(*_GRAPH_KINDS, "symbol")):
                payload = row["payload"] if isinstance(row["payload"], Mapping) else {}
                result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
                kind = str(row["kind"])
                path = (row.get("location") or {}).get("path")
                if kind == "symbol":
                    location = row.get("location") or {}
                    if path and location.get("start_line") and payload.get("kind") == "function":
                        symbol = _Symbol(str(row["identity"]), str(payload.get("qualified_name") or row["native_id"]),
                                         str(path), int(location["start_line"]), location.get("file_sha256"), sha)
                        self.symbols[symbol.identity] = symbol
                        self.symbols_by_path[symbol.path].append(symbol)
                    continue
                families.add(kind)
                unit = _nested(payload, "scope", "build_unit_id")
                if isinstance(unit, str) and unit:
                    units.add(unit)
                scope_id = _nested(payload, "scope", "scope_id")
                if isinstance(scope_id, str) and scope_id:
                    scope_ids.add(scope_id)
                if path:
                    paths.add(str(path))
                line = (row.get("location") or {}).get("start_line")
                if kind == "call_site":
                    caller, callee = result.get("caller") or {}, result.get("callee") or {}
                    call = _Call(str(row["identity"]), _identity_or_none(caller.get("symbol")),
                                 function_tail(caller.get("display")), _identity_or_none(callee.get("symbol")),
                                 function_tail(callee.get("display")), str(path) if path else None,
                                 int(line) if line else None, sha, summarize_fact(kind, payload))
                    self.calls.append(call)
                    if path and line:
                        self.enclosing[(str(path), int(line))].add((call.caller_symbol, call.caller_name))
                elif kind == "sink_site" and path and line:
                    function = result.get("enclosing_function") or {}
                    self.enclosing[(str(path), int(line))].add(
                        (_identity_or_none(function.get("symbol")), function_tail(function.get("display"))))
                klass = (result.get("sink_class") if kind == "sink_site" else
                         result.get("source_class") if kind == "entry_point" else None)
                self.facts[str(row["identity"])] = _Fact(
                    str(row["identity"]), kind, str(path) if path else None,
                    str(klass) if isinstance(klass, str) and klass else None,
                    _identity_or_none(_nested(result, "sink", "sink_site")),
                    _identity_or_none(_nested(result, "source", "entry_point")), sha,
                    int(line) if line else None, _identity_or_none(_nested(result, "enclosing_function", "symbol")),
                    summarize_fact(kind, payload, line=int(line) if line else None))
            state, reason = _shard_state(store.coverage((shard,)))
            self.shards.append(_GraphShard(f"{shard['name']}/{shard.get('shard_id', 'default')}", sha,
                                           frozenset(families), frozenset(units), frozenset(paths),
                                           frozenset(scope_ids), state, reason))
        for items in self.symbols_by_path.values():
            items.sort(key=lambda item: (item.line, item.identity))
        self.calls_by_id = {call.identity: call for call in self.calls}
        self.calls_by_callee_symbol: dict[str, list[_Call]] = defaultdict(list)
        self.calls_by_callee_name: dict[str, list[_Call]] = defaultdict(list)
        for call in self.calls:
            if call.callee_symbol:
                self.calls_by_callee_symbol[call.callee_symbol].append(call)
            self.calls_by_callee_name[call.callee_name].append(call)
        for relation in store.relations(shards, kinds=("DERIVED_FROM",)):
            source = self.facts.get(str(relation["source_id"]))
            if (source is not None and source.kind == "dataflow_path"
                    and _nested(relation["payload"], "state") in CORRELATED_STATES):
                self.correlated[str(relation["target_id"])].add(source.identity)
        # Indexes for package neighborhoods: facts by enclosing function, by sink, and by source line.
        self.by_function: dict[str, list[_Fact]] = defaultdict(list)
        self.by_sink: dict[str, list[_Fact]] = defaultdict(list)
        self.at_line: dict[tuple[str, int], list[_Fact]] = defaultdict(list)
        for fact in sorted(self.facts.values(), key=lambda item: (item.line or 0, item.identity)):
            if fact.function:
                self.by_function[fact.function].append(fact)
            if fact.sink and fact.kind in {"guard_fact", "range_fact", "dataflow_path"}:
                self.by_sink[fact.sink].append(fact)
            if fact.path and fact.line:
                self.at_line[(fact.path, fact.line)].append(fact)

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

    def enclosing_functions(self, path: str | None, line: int | None) -> set[tuple[str | None, str]]:
        """(symbol, unqualified name) of the functions graph facts place on one source line."""
        if not path or not line:
            return set()
        return {item for item in self.enclosing.get((str(path), int(line)), set()) if item[1]}

    def callers(self, functions: Iterable[tuple[str | None, str]], *, depth: int, limit: int
                ) -> tuple[list[ContextEntry], int, bool]:
        """``call_site`` facts reaching ``functions``, breadth-first to ``depth``, at most ``limit``.

        A call matches by callee symbol when both sides have one, and otherwise by unqualified name
        (``secondary_only`` facts from SVF or clangd carry no callee symbol). Returns the entries in
        (depth, identity) order, the number of matches beyond ``limit``, and whether any match was by
        name, which a caller of this method reports as an ambiguity gap.
        """
        frontier = {(symbol, name) for symbol, name in functions if name}
        seen_functions = set(frontier)
        chosen: list[ContextEntry] = []
        taken: set[str] = set()
        omitted = 0
        by_name = False
        for _level in range(depth):
            symbols = {symbol for symbol, _name in frontier if symbol}
            names = {name for _symbol, name in frontier}
            unsymbolled = {name for symbol, name in frontier if not symbol}
            matches = []
            for call in self.calls:
                if call.identity in taken:
                    continue
                if call.callee_symbol is not None and call.callee_symbol in symbols:
                    matches.append(call)
                elif call.callee_name in (names if call.callee_symbol is None else unsymbolled):
                    matches.append(call)
                    by_name = True
            matches.sort(key=lambda item: item.identity)
            next_frontier: set[tuple[str | None, str]] = set()
            for call in matches:
                taken.add(call.identity)
                if len(chosen) < limit:
                    chosen.append(context_entry(call.identity, CALLER_ROLE, call.shard_sha256))
                else:
                    omitted += 1
                caller = (call.caller_symbol, call.caller_name)
                if call.caller_name and caller not in seen_functions:
                    seen_functions.add(caller)
                    next_frontier.add(caller)
            if not next_frontier:
                break
            frontier = next_frontier
        return chosen, omitted, by_name

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


    # -- package neighborhood (package-neighborhood/1) --------------------------------------------------
    def function_at(self, path: str | None, line: int | None) -> tuple[_Symbol | None, str]:
        """The function a lead line belongs to and how it was chosen.

        A function that a sink or call fact on the line names is exact. Otherwise the nearest preceding
        function definition in the same file is used and the choice is recorded as an inference.
        """
        if not path or not line:
            return None, "none"
        direct = sorted(symbol for symbol, _name in self.enclosing_functions(path, line) if symbol in self.symbols)
        if direct:
            return self.symbols[direct[0]], "enclosing_fact_on_line"
        best = None
        for item in self.symbols_by_path.get(str(path), ()):
            if item.line <= int(line):
                best = item
            else:
                break
        return (best, "nearest_preceding_definition") if best else (None, "none")

    def _walk(self, functions: Iterable[tuple[str | None, str]], *, direction: str, depth: int, limit: int
              ) -> tuple[list[NeighborhoodRow], int, bool]:
        """Call sites reaching (``callers``) or leaving (``callees``) ``functions``, breadth-first to ``depth``."""
        frontier = {(symbol, name) for symbol, name in functions if name}
        seen_functions = set(frontier)
        taken: set[str] = set()
        rows: list[NeighborhoodRow] = []
        omitted, by_name = 0, False
        role = "caller" if direction == "callers" else "callee"
        for level in range(1, depth + 1):
            symbols = {symbol for symbol, _name in frontier if symbol}
            names = {name for _symbol, name in frontier}
            unsymbolled = {name for symbol, name in frontier if not symbol}
            matches = []
            for call in self.calls:
                if call.identity in taken:
                    continue
                if direction == "callers":
                    near_symbol, near_name = call.callee_symbol, call.callee_name
                else:
                    near_symbol, near_name = call.caller_symbol, call.caller_name
                if near_symbol is not None and near_symbol in symbols:
                    matches.append(call)
                elif near_name in (names if near_symbol is None else unsymbolled):
                    matches.append(call)
                    by_name = True
            matches.sort(key=lambda item: item.identity)
            following: set[tuple[str | None, str]] = set()
            for call in matches:
                taken.add(call.identity)
                if len(rows) < limit:
                    rows.append(NeighborhoodRow(call.identity, role, call.summary, call.line, {"depth": level}))
                else:
                    omitted += 1
                far = ((call.caller_symbol, call.caller_name) if direction == "callers"
                       else (call.callee_symbol, call.callee_name))
                if far[1] and far not in seen_functions:
                    seen_functions.add(far)
                    following.add(far)
            if not following:
                break
            frontier = following
        return rows, omitted, by_name

    def entry_chain(self, functions: Iterable[tuple[str | None, str]], depth: int
                    ) -> tuple[list[NeighborhoodRow], list[NeighborhoodRow], bool, bool]:
        """The upward call chain from ``functions`` to the nearest function holding an ``entry_point`` fact.

        Breadth-first over call sites to ``depth`` levels (existing ``CALLS`` edges: ``call_site`` facts), the
        shallowest level that reaches an entry point wins and ties break by identity, so the chain is
        deterministic. Returns (hops from the lead\'s function upward, entry points reached, reached, matched by
        name). ``reached`` is false when no entry point lies within ``depth`` levels; that is a gap, not a finding.
        """
        start = sorted({(symbol, name) for symbol, name in functions if name}, key=repr)

        def entries_of(nodes: Iterable[tuple[str | None, str]]) -> list[NeighborhoodRow]:
            facts = {fact.identity: fact for symbol, _name in nodes if symbol
                     for fact in self.by_function.get(symbol, ()) if fact.kind == "entry_point"}
            return [NeighborhoodRow(fact.identity, "entry_point", fact.summary, fact.line)
                    for fact in sorted(facts.values(), key=lambda item: item.identity)]

        found = entries_of(start)
        if found:
            return [], found, True, False
        parents: dict[tuple[str | None, str], tuple[tuple[str | None, str], _Call]] = {}
        seen = set(start)
        frontier = list(start)
        by_name = False
        for _level in range(depth):
            following: list[tuple[str | None, str]] = []
            for node in frontier:
                symbol, name = node
                matches = {call.identity: call for call in self.calls_by_callee_symbol.get(symbol, ())} if symbol else {}
                for call in self.calls_by_callee_name.get(name, ()):
                    if call.callee_symbol is None or not symbol:
                        matches.setdefault(call.identity, call)
                        by_name = True
                for call in sorted(matches.values(), key=lambda item: item.identity):
                    far = (call.caller_symbol, call.caller_name)
                    if not far[1] or far in seen:
                        continue
                    seen.add(far)
                    parents[far] = (node, call)
                    reached = entries_of([far])
                    if reached:
                        hops: list[NeighborhoodRow] = []
                        cursor = far
                        while cursor in parents:
                            cursor, via = parents[cursor][0], parents[cursor][1]
                            hops.append(NeighborhoodRow(via.identity, "caller", via.summary, via.line))
                        hops.reverse()
                        hops = [NeighborhoodRow(hop.ref, hop.role, hop.summary, hop.line, {"depth": number})
                                for number, hop in enumerate(hops, start=1)]
                        return hops, reached, True, by_name
                    following.append(far)
            if not following:
                break
            frontier = following
        return [], [], False, by_name

    def neighborhood(self, path: str | None, line: int | None, settings: GraphSettings, subject: str
                     ) -> tuple[dict[str, Any], list[ContextEntry], list[ScopeGap]]:
        """The ``package-neighborhood/1`` record for one lead location, its context entries and gaps."""
        record = empty_record(settings.max_call_depth)
        gaps: list[ScopeGap] = []
        if not self.available or not path or not line:
            return record, [], gaps
        fn, basis = self.function_at(path, line)
        symbol = fn.identity if fn else None
        omitted = record["omitted"]
        rows: dict[str, list[NeighborhoodRow]] = {section: [] for section in NEIGHBORHOOD_SECTIONS}

        chosen = {fact.identity: fact for fact in self.at_line.get((str(path), int(line)), ()) if fact.kind == "sink_site"}
        if symbol:
            chosen.update((fact.identity, fact) for fact in self.by_function.get(symbol, ()) if fact.kind == "sink_site")
        ordered = sorted(chosen.values(), key=lambda fact: (abs((fact.line or 0) - int(line)), fact.line or 0, fact.identity))
        sinks = ordered[:settings.max_neighbors_per_function]
        omitted["sinks"] = len(ordered) - len(sinks)
        rows["sinks"] = [NeighborhoodRow(fact.identity, "sink", fact.summary, fact.line) for fact in sinks]
        flow_facts: list[_Fact] = []
        for sink in sinks:
            related = self.by_sink.get(sink.identity, ())
            for kind, section, role, bound in (("range_fact", "ranges", "range", settings.max_guards_per_sink),
                                               ("guard_fact", "guards", "guard", settings.max_guards_per_sink),
                                               ("dataflow_path", "flows", "path", settings.max_paths_per_sink)):
                members = [fact for fact in related if fact.kind == kind]
                rows[section].extend(NeighborhoodRow(fact.identity, role, fact.summary, fact.line)
                                     for fact in members[:bound])
                omitted[section] += max(0, len(members) - bound)
                if kind == "dataflow_path":
                    flow_facts.extend(members[:bound])
        entry_ids = {fact.entry for fact in flow_facts if fact.entry}
        entry_facts = {fact.identity: fact for fact in self.by_function.get(symbol, ()) if fact.kind == "entry_point"} \
            if symbol else {}
        entry_facts.update((identity, self.facts[identity]) for identity in entry_ids if identity in self.facts)
        entries = sorted(entry_facts.values(), key=lambda fact: (fact.line or 0, fact.identity))
        rows["entries"] = [NeighborhoodRow(fact.identity, "entry_point", fact.summary, fact.line)
                           for fact in entries[:settings.max_neighbors_per_function]]
        omitted["entries"] = max(0, len(entries) - settings.max_neighbors_per_function)
        functions = set(self.enclosing_functions(path, line))
        if fn:
            functions.add((fn.identity, function_tail(fn.name)))
        by_name = False
        for direction, section in (("callers", "callers"), ("callees", "callees")):
            found, dropped, named = self._walk(functions, direction=direction, depth=settings.max_call_depth,
                                               limit=settings.max_neighbors_per_function)
            rows[section], omitted[section], by_name = found, dropped, by_name or named
        if by_name:
            gaps.append(ScopeGap("code_graph_neighborhood", subject, "ambiguous",
                                 "some callers or callees were matched by unqualified function name because a call "
                                 "site or the function has no symbol; overloads and same-named functions may be included"))
        hops, reached_entries, reached, chain_by_name = self.entry_chain(functions, settings.max_call_depth)
        record["chain"] = {"reached": reached, "depth_limit": settings.max_call_depth,
                           "hops": [row.record() for row in hops], "entries": [row.record() for row in reached_entries]}
        if chain_by_name and reached:
            by_name = True
        if not reached:
            gaps.append(ScopeGap(
                "code_graph_neighborhood", subject, "unavailable",
                f"no entry_point fact is reachable from the lead\'s function within {settings.max_call_depth} call "
                "levels of accepted call sites; whether an attacker can reach the lead is unknown, not excluded"))
        context: list[ContextEntry] = [
            context_entry(row.ref, row.role, self.calls_by_id[row.ref].shard_sha256 if row.ref in self.calls_by_id
                          else self.facts[row.ref].shard_sha256 if row.ref in self.facts else None)
            for row in (*hops, *reached_entries)]
        if fn:
            record["function"] = {"symbol": fn.identity, "name": fn.name, "path": fn.path, "start_line": fn.line,
                                  "file_sha256": fn.file_sha256, "basis": basis}
            context.append(context_entry(fn.identity, "function", fn.shard_sha256))
            if basis != "enclosing_fact_on_line":
                gaps.append(ScopeGap("code_graph_neighborhood", subject, "ambiguous",
                                     f"the lead's function {fn.name} is the nearest preceding definition in the file, "
                                     "not a function a fact on the lead's line names"))
        else:
            gaps.append(ScopeGap("code_graph_neighborhood", subject, "unavailable",
                                 "no accepted graph symbol places the lead's line inside a known function; only facts "
                                 "on the line itself are listed"))
        if not sinks:
            gaps.append(ScopeGap("code_graph_neighborhood", subject, "unavailable",
                                 "no accepted sink_site fact is located in the lead's function or on its line; absence "
                                 "of a sink fact is a gap, not evidence that the code has no sink"))
        for section in NEIGHBORHOOD_SECTIONS:
            record[section] = [row.record() for row in rows[section]]
            for row in rows[section]:
                fact = self.facts.get(row.ref)
                context.append(context_entry(row.ref, row.role, fact.shard_sha256 if fact else
                                             self.calls_by_id[row.ref].shard_sha256 if row.ref in self.calls_by_id
                                             else None))
        dropped = {key: value for key, value in omitted.items() if value}
        if dropped:
            gaps.append(ScopeGap("code_graph_neighborhood", subject, "truncated",
                                 "neighborhood rows exceeded the code-graph bounds and were omitted: "
                                 + ", ".join(f"{key}={value}" for key, value in sorted(dropped.items()))))
        return record, context, gaps

    def unit_neighborhood(self, entries: Iterable[ContextEntry], depth: int) -> dict[str, Any]:
        """The neighborhood record of a hunt package: summaries of its embedded sink and entry-point facts."""
        record = empty_record(depth)
        for entry in sorted(entries, key=lambda item: (item.role, item.id)):
            fact = self.facts.get(entry.id)
            section = {"sink": "sinks", "entry_point": "entries"}.get(entry.role)
            if fact is not None and section is not None:
                record[section].append(NeighborhoodRow(fact.identity, entry.role, fact.summary, fact.line).record())
        return record


class _Assembler:
    def __init__(self, scope: AcceptedScope, settings: PackageSettings, collection: LeadCollection,
                 cwe_reference: CweReference | None = None, graph_settings: GraphSettings | None = None):
        self.scope = scope
        self.settings = settings
        self.graph_settings = graph_settings if graph_settings is not None else GraphSettings()
        self.build_context = BuildContext(scope)
        self.artifacts = ArtifactContext(scope)
        self.artifact_context = {
            lead.observation_id: self.artifacts.for_lead(lead, limit=settings.max_context_entries)
            for lead in collection.leads if any(role == "artifact" for _, role in lead.related)
        }
        self.at_location: dict[tuple[str, int], list[Lead]] = defaultdict(list)
        for lead in collection.leads:
            if lead.path and lead.start_line:
                self.at_location[(lead.path, lead.start_line)].append(lead)
        self.collection = collection
        self.correlation_hashes = tuple(sorted(str(item["sha256"]) for item in collection.correlation_shards))
        self.extra_gaps: list[ScopeGap] = []
        self.cwe_reference = cwe_reference
        self.reference_weaknesses = _reference_weaknesses(scope)
        self.graph = GraphContext(scope)
        self.memory = MemoryContext(scope, max_entries=settings.max_memory_context_entries)
        self.routing_tags: dict[str, list[ContextEntry]] = defaultdict(list)
        self.control_context: dict[str, list[ContextEntry]] = defaultdict(list)
        from appsec_review.indexing.products import load_control_assessment
        control_cache: dict[str, Any] = {}
        for shard in scope.producer("control_evidence").shards:
            for row in scope.store.entities((shard,), kinds=("precomputed_fact",)):
                result = row["payload"].get("result", {})
                if result.get("assessment_mode") != "assessment":
                    continue
                result = load_control_assessment(scope.run_root, scope.target_snapshot, result, cache=control_cache)
                cid = str(result.get("component_id"))
                self.control_context[cid].append(context_entry(row["identity"], "control_context",
                    scope.shard_sha256(shard), control_assessment=result))
        for shard in scope.producer("security_tagging").shards:
            for row in scope.store.entities((shard,), kinds=("tag_assignment",)):
                subject = row["payload"].get("subject") or {}
                keys = [subject.get("logical_id"), subject.get("path")]
                if subject.get("kind") == "component":
                    keys.append(subject.get("component_id"))
                for key in {key for key in keys if isinstance(key, str) and key}:
                    self.routing_tags[key].append(context_entry(row["identity"], "tag",
                                                               shard_sha256=scope.shard_sha256(shard)))

    def scoped_tags(self, component_id: str, source_ids: Iterable[str], paths: Iterable[str]) -> list[ContextEntry]:
        return [entry for key in {component_id, *source_ids, *paths} for entry in self.routing_tags.get(key, ())]

    def corroboration(self, lead: Lead) -> tuple[list[NeighborhoodRow], int]:
        """Other observations on the lead's own line, strongest first, bounded by ``MAX_CORROBORATION``."""
        if not lead.path or not lead.start_line:
            return [], 0
        others = sorted((item for item in self.at_location.get((lead.path, lead.start_line), ())
                         if item.observation_id != lead.observation_id),
                        key=lambda item: (SEVERITY_ORDER[item.reported_severity], item.observation_id))
        rows = [NeighborhoodRow(item.observation_id, "corroboration", f"{item.scanner} {item.rule_id}: "
                                f"{(item.message or '')[:120]}".strip(), item.start_line,
                                {"scanner": item.scanner, "rule": item.rule_id,
                                 "severity": item.reported_severity, "relation": "same_location"})
                for item in others[:MAX_CORROBORATION]]
        return rows, max(0, len(others) - MAX_CORROBORATION)

    def lead_neighborhood(self, lead: Lead, subject: str, unit_id: str | None
                          ) -> tuple[dict[str, Any], list[ContextEntry], list[ScopeGap]]:
        """Neighborhood record, context entries and gaps of a lane A lead."""
        record, entries, gaps = self.graph.neighborhood(lead.path, lead.start_line, self.graph_settings, subject)
        rows, dropped = self.corroboration(lead)
        record["corroboration"] = [row.record() for row in rows]
        record["omitted"]["corroboration"] = dropped
        entries.extend(context_entry(row.ref, row.role) for row in rows)
        build = self.build_context.summary(lead.path)
        if build is not None:
            record["build"] = build
            entries.append(context_entry(build["ref"], "build"))
        elif lead.path and Path(lead.path).suffix.lower() in C_FAMILY_SUFFIXES:
            gaps.append(ScopeGap("build_provenance", subject, "unavailable" if self.build_context.available else "missing",
                                 "no accepted build command fact compiles this file; compiler, flags and hardening are "
                                 "unknown for it, not absent"))
        return record, entries, gaps

    @staticmethod
    def trim_neighborhood(record: dict[str, Any], entries: list[ContextEntry]) -> bool:
        """Drop the least valuable neighborhood row to respect ``max_package_bytes``; False when none is left."""
        for section in ("corroboration", "callees", "callers", "flows", "entries", "guards", "ranges", "sinks"):
            if record[section]:
                row = record[section].pop()
                record["omitted"][section] += 1
                entries[:] = [item for item in entries if item.id != row["ref"] or item.role == "build"
                              or any(other["ref"] == row["ref"] for name in NEIGHBORHOOD_SECTIONS
                                     for other in record[name])]
                return True
        return False

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
        artifacts = self.artifact_context.get(lead.observation_id, ([], [], ()))[0]
        path = lead.path or next((item["workspace_path"] for item in artifacts if item["workspace_path"]), None)
        component = self.scope.component_for(path)
        unit = self.scope.build_unit_for(path)
        if component is None and lead.component_hint:
            component = next((item for item in self.scope.components
                              if item.component_id == lead.component_hint), None)
        if unit is None and lead.build_unit_hint:
            unit = next((item for item in self.scope.build_units
                         if item.build_unit_id == lead.build_unit_hint), None)
        return (component.component_id if component else lead.component_hint or "unassigned",
                unit.build_unit_id if unit else None, component, unit)

    @staticmethod
    def _context_order(entry: ContextEntry) -> tuple[str, int, str, str]:
        assessment = entry.control_assessment or {}
        assessed = assessment.get("control_status") in {"satisfied", "not_satisfied"} or any(
            item.get("resolved") is True and item.get("locator", {}).get("kind") == "source"
            for item in assessment.get("evidence", ()))
        return (entry.role, int(bool(assessment) and not assessed),
                str(assessment.get("control_identity", "")), entry.id)

    def _cap(self, context: Iterable[ContextEntry], subject: str, producer: str
             ) -> tuple[list[ContextEntry], int, list[ScopeGap]]:
        unique = {(item.role, item.id): item for item in context}
        ordered = sorted(unique.values(), key=self._context_order)
        bound = self.settings.max_context_entries
        if len(ordered) <= bound:
            return ordered, 0, []
        # Preserve representation from every context role under pressure. In particular, a large
        # dependency inventory must not consume the whole budget before its Scorecard seeds are
        # admitted. Within the control role, assessed/source-backed evidence precedes declarations.
        buckets = {role: [entry for entry in ordered if entry.role == role]
                   for role in sorted({key[0] for key in unique})}
        balanced: list[ContextEntry] = []
        depth = 0
        while len(balanced) < bound and any(depth < len(bucket) for bucket in buckets.values()):
            for bucket in buckets.values():
                if depth < len(bucket) and len(balanced) < bound:
                    balanced.append(bucket[depth])
            depth += 1
        omitted = len(ordered) - bound
        return balanced, omitted, [ScopeGap(producer, subject, "truncated",
                                                   f"{omitted} context entr{'y' if omitted == 1 else 'ies'} "
                                                   f"exceeded max_context_entries={bound}")]

    def _build(self, *, kind: str, lead_family: str | None, scope_record: Mapping[str, Any],
               partition: tuple[int, int], rank: Mapping[str, Any] | None, menu: list[tuple[Lead, str, str | None]],
               context: list[ContextEntry], obligations: Iterable[Predicate], gaps: Iterable[ScopeGap],
               truncation: Mapping[str, Any], graph_families: Iterable[str] = (),
               graph_shards: Iterable[str] = (), graph_scopes: Iterable[str] = (),
               neighborhood: Mapping[str, Any] | None = None) -> tuple[str, bytes]:
        leads = sorted(menu, key=lambda item: (SEVERITY_ORDER[item[0].effective_severity], item[0].observation_id))
        lead_ids = sorted(item[0].observation_id for item in leads)
        artifact_records = {
            lead.observation_id: [
                record if kind == "finding_lead" else {
                    **record, "provenance": [],
                    "provenance_omitted": record["provenance_omitted"] + len(record["provenance"])}
                for record in self.artifact_context.get(lead.observation_id, ([],))[0]]
            for lead, *_ in leads}
        artifact_refs = set()
        for records in artifact_records.values():
            for artifact in records:
                artifact_refs.add(artifact["identity"])
                for relation in artifact["provenance"]:
                    artifact_refs.update((relation["source_id"], relation["target_id"]))
                    artifact_refs.update(command["ref"] for command in relation["commands"])
        assessments = [lead.control_assessment for lead, *_ in leads if lead.control_assessment is not None]
        assessments.extend(item.control_assessment for item in context if item.control_assessment is not None)
        underlying = [item for assessment in assessments for item in assessment["evidence"] if item["resolved"]]
        entities = sorted({*lead_ids, *scope_record["source_ids"], *scope_record["artifact_ids"],
                           *(item.id for item in context), *artifact_refs,
                           *(item["source_identity"] for item in underlying)})
        shard_hashes = sorted({*(item[0].shard_sha256 for item in leads),
                               *(item.shard_sha256 for item in context if item.shard_sha256), *graph_shards,
                               *(item["publication"]["sha256"] for item in underlying),
                               *(assessment["workbench_reference"]["manifest_sha256"] for assessment in assessments),
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
                                            "graph_context": GRAPH_CONTEXT_RULE,
                                            "memory_context": MEMORY_CONTEXT_RULE,
                                            "neighborhood": NEIGHBORHOOD_RULE, "fact_summary": SUMMARY_RULE,
                                            "build_summary": BUILD_RULE},
            "cwe_reference": self.cwe_reference.record() if self.cwe_reference is not None else None,
            "caps": self.settings.record(), "graph_caps": asdict(self.graph_settings)})
        body = {
            "schema": PACKAGE_SCHEMA, "kind": kind, "lane": "lead" if kind == "finding_lead" else "hunt",
            "lead_family": lead_family, "run_id": self.scope.run_id, "manifest_sha256": self.scope.manifest_sha256,
            "target_snapshot": self.scope.target_snapshot, "input_fingerprint": fingerprint,
            "assembly_rule": ASSEMBLY_RULE, "scope": dict(scope_record),
            "partition": {"number": partition[0], "count": partition[1]}, "rank": rank,
            "persona": None, "stack_profile": None,
            "lead_menu": [{**lead_record(*item, weaknesses=self.weaknesses(item[0]),
                                      admission=admission_reasons(item[0], self.settings)
                                      if kind == "finding_lead" else None),
                           **({"artifacts": artifact_records[item[0].observation_id]}
                              if artifact_records[item[0].observation_id] else {})}
                          for item in leads],
            "evidence": sorted((_evidence(item[0]) for item in leads), key=lambda value: value["entity_id"]),
            "context": [item.record() for item in context],
            "neighborhood": dict(neighborhood) if neighborhood is not None
            else empty_record(self.graph_settings.max_call_depth),
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
        context.extend(self.scoped_tags(component_id, sources, (lead.path,) if lead.path else ()))
        context.extend(self.control_context.get(component_id, ()))
        if lead.duplicate_of:
            context.append(context_entry(lead.duplicate_of, "duplicate_of"))
        context.extend(context_entry(identity, "flow") for identity in lead.flow_ids)
        artifact_records, artifact_entries, artifact_gaps = self.artifact_context.get(
            lead.observation_id, ([], [], ()))
        binary_only = bool(artifact_records) and lead.path is None
        context.extend(artifact_entries)
        context.extend(self.graph.lead_context(lead.observation_id))
        partition_key = f"lead/{lead.observation_id}"
        memory = self.memory.lead_context(lead.path, lead.start_line, partition_key)
        context.extend(memory.entries)
        context_gaps = list(memory.gaps)
        functions = self.graph.enclosing_functions(lead.path, lead.start_line) | {
            (None, name) for name in memory.functions}
        if functions:
            callers, caller_omitted, by_name = self.graph.callers(
                functions, depth=self.settings.caller_depth, limit=self.settings.max_callers)
            context.extend(callers)
            if caller_omitted:
                context_gaps.append(ScopeGap(CALLER_PRODUCER, partition_key, "truncated",
                                             f"{caller_omitted} caller call site(s) exceeded max_callers="
                                             f"{self.settings.max_callers}"))
            if by_name:
                context_gaps.append(ScopeGap(CALLER_PRODUCER, partition_key, "ambiguous",
                                             "some callers were matched by unqualified function name because a "
                                             "call site or the enclosing function has no symbol; overloads and "
                                             "same-named functions may be included"))
        elif lead.path and lead.start_line and self.graph.available:
            context_gaps.append(ScopeGap(CALLER_PRODUCER, partition_key, "unavailable",
                                         "no accepted fact names the function enclosing the lead's line; callers "
                                         "are not listed"))
        families, graph_shards, graph_gaps = (self.graph.families(
            unit_id, (lead.path,) if lead.path else (), partition_key) if not binary_only else ([], [], []))
        capped, omitted, gaps = self._cap(context, partition_key, lead.family)
        neighborhood, nb_entries, nb_gaps = self.lead_neighborhood(lead, partition_key, unit_id)
        gaps.extend(nb_gaps)
        gaps.extend(graph_gaps)
        gaps.extend(context_gaps)
        gaps.extend(lead.coverage_gaps)
        gaps.extend(artifact_gaps)
        subjects = {lead.observation_id, partition_key, *(identity for identity, _ in lead.related)}
        if lead.path:
            subjects.add(lead.path)
        gaps.extend(gap for gap in self.collection.gaps if gap.scope in subjects)
        # Reference-feed limitations belong only to the advisories actually joined to this lead.
        for advisory in (lead.advisory or {}).get("advisories", ()):
            for feed, reference in advisory.get("feeds", {}).items():
                if reference.get("stale"):
                    gaps.append(ScopeGap(feed, partition_key, "stale", "joined advisory reference feed is stale"))
            gaps.extend(ScopeGap("advisory_reference", partition_key, "partial", str(reason))
                        for reason in advisory.get("gaps", ()))
        if not lead.location_exact and not artifact_records:
            gaps.append(ScopeGap(lead.family, partition_key, "ambiguous",
                                 "lead location is unresolved or ambiguous; no source line is cited"))
        scope_record = {"component_id": component_id, "trust_boundary_id": None, "build_unit_id": unit_id,
                        "partition_key": partition_key, "source_ids": sorted(sources), "artifact_ids": sorted(artifacts)}
        trimmed = 0
        while True:
            merged = {(item.role, item.id): item for item in (*capped, *nb_entries)}
            visible = gaps + ([ScopeGap("code_graph_neighborhood", partition_key, "truncated",
                                        f"{trimmed} neighborhood row(s) omitted to respect max_package_bytes")]
                              if trimmed else [])
            package_id, body = self._build(
                kind="finding_lead", lead_family=lead.family, scope_record=scope_record, partition=(0, 1), rank=None,
                menu=[(lead, component_id, unit_id)], context=[merged[key] for key in sorted(merged)],
                obligations=OBLIGATIONS[lead.family],
                gaps=visible, truncation={"omitted_leads": 0, "omitted_context": omitted, "next_partition": None},
                graph_families=families, graph_shards=graph_shards,
                graph_scopes=self.graph.scopes(unit_id, (lead.path,) if lead.path else ()) if not binary_only else (),
                neighborhood=neighborhood)
            if len(body) <= self.settings.max_package_bytes:
                gaps = visible
                break
            if self.trim_neighborhood(neighborhood, nb_entries):
                trimmed += 1
                continue
            if not capped:
                raise IntegrityError(f"finding-lead package for {lead.observation_id} exceeds max_package_bytes and "
                                     "cannot be partitioned; the membership gate is blocked")
            capped = capped[:-1]
            omitted += 1
            gaps = [gap for gap in gaps if gap.state != "truncated" or gap.producer == "code_graph_neighborhood"] + [ScopeGap(
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
        context, omitted, gaps = self._cap(
            (*unit.context, *graph_context, *self.scoped_tags(unit.component_id, unit.source_ids, unit.paths),
             *self.control_context.get(unit.component_id, ())),
            unit.key, "lane_b_hunt")
        if graph_omitted:
            omitted += graph_omitted
            gaps.append(ScopeGap(GRAPH_PRODUCER, unit.key, "truncated",
                                 f"{graph_omitted} graph context entr{'y' if graph_omitted == 1 else 'ies'} "
                                 f"exceeded max_context_entries={bound}"))
        families, graph_shards, graph_gaps = self.graph.families(unit.build_unit_id, unit.paths, unit.key)
        graph_scopes = self.graph.scopes(unit.build_unit_id, unit.paths)
        neighborhood = self.graph.unit_neighborhood(context, self.graph_settings.max_call_depth)
        missing = [gap for gap in (*self.scope.gaps, *self.collection.gaps) if gap.state == "missing"]
        scope_record = {"component_id": unit.component_id, "trust_boundary_id": unit.trust_boundary_id,
                        "build_unit_id": unit.build_unit_id, "source_ids": list(unit.source_ids),
                        "artifact_ids": sorted({identity for lead in unit.leads for identity, role in lead.related
                                                if role == "artifact"})}
        rank = ranked.rank_record()
        byte_omitted_controls = 0

        def control_gaps() -> list[ScopeGap]:
            return ([ScopeGap("owasp_control", unit.key, "truncated",
                f"{byte_omitted_controls} control context entries exceeded max_package_bytes="
                f"{self.settings.max_package_bytes}; all control rows remain in the pinned OWASP workbench")]
                if byte_omitted_controls else [])

        def render(chunk: list, number: int, count: int) -> tuple[str, bytes]:
            key = f"{unit.key}#{number:05d}"
            following = f"{unit.key}#{number + 1:05d}" if number + 1 < count else None
            return self._build(
                kind="hunt", lead_family=None, scope_record={
                    **scope_record, "partition_key": key,
                    "artifact_ids": sorted({identity for lead, *_ in chunk for identity, role in lead.related
                                            if role == "artifact"})},
                partition=(number, count), rank=rank, menu=chunk, context=context, obligations=OBLIGATIONS["hunt"],
                gaps=[*gaps, *graph_gaps, *missing, *control_gaps()],
                truncation={"omitted_leads": 0, "omitted_context": omitted, "next_partition": following},
                graph_families=families, graph_shards=graph_shards, graph_scopes=graph_scopes,
                neighborhood=neighborhood)

        def split(chunk: list) -> list[list]:
            nonlocal omitted, byte_omitted_controls
            _identity, body = render(chunk, 99_997, 99_999)  # include the non-final continuation pointer
            if len(body) <= self.settings.max_package_bytes:
                return [chunk]
            if len(chunk) <= 1:
                # Splitting leads cannot reduce component-wide control context. Apply the same
                # explicit byte-bound qualification as lane A, without removing authoritative rows.
                while len(body) > self.settings.max_package_bytes:
                    candidates = [i for i, entry in enumerate(context) if entry.control_assessment is not None]
                    if not candidates:
                        break
                    context.pop(max(candidates, key=lambda i: self._context_order(context[i])))
                    omitted += 1
                    byte_omitted_controls += 1
                    _identity, body = render(chunk, 99_997, 99_999)
                if len(body) <= self.settings.max_package_bytes:
                    return [chunk]
                raise IntegrityError(f"hunt partition of {unit.key} exceeds max_package_bytes with a single lead; "
                                     "the membership gate is blocked")
            middle = len(chunk) // 2
            return split(chunk[:middle]) + split(chunk[middle:])

        size = self.settings.hunt_menu_partition_size
        chunks = [chunk for offset in range(0, max(1, len(menu)), size)
                  for chunk in split(menu[offset:offset + size])]
        self.extra_gaps.extend((*gaps, *control_gaps()))
        packages = []
        for number, chunk in enumerate(chunks):
            package_id, body = render(chunk, number, len(chunks))
            if len(body) > self.settings.max_package_bytes:
                raise IntegrityError(f"hunt partition of {unit.key} exceeds max_package_bytes after numbering")
            packages.append(Package(package_id, "hunt", "hunt", None, f"{unit.key}#{number:05d}",
                                    tuple(sorted(item[0].observation_id for item in chunk)), unit.key, body))
        return packages


def audit_membership(collection: LeadCollection, packages: Iterable[Package],
                     admit: Iterable[str], admit_kev: bool = False, exploration_enabled: bool = False,
                     exploration_reserve: int = 1) -> dict[str, Any]:
    """Gate 5 for lane A: E ⊆ F per family and severity, exactly once, with no invented lead.

    ``E`` holds every lead whose effective severity is admitted and, with ``admit_kev``, every
    KEV-listed lead whatever its effective severity.
    """
    admitted = set(admit)
    expected = {lead.observation_id: lead for lead in admitted_leads(
        collection, PackageSettings(admit_severities=tuple(admitted), admit_kev=admit_kev,
                                    exploration_enabled=exploration_enabled,
                                    exploration_reserve=exploration_reserve))}
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
    severities = admitted | {lead.effective_severity for lead in expected.values()}
    for family in FAMILIES:
        by_cell[family] = {}
        for severity in sorted(severities, key=SEVERITY_ORDER.__getitem__):
            members = [key for key, lead in expected.items() if lead.family == family
                       and lead.effective_severity == severity]
            packaged = sum(seen[key] for key in members)
            if packaged != len(members):
                raise IntegrityError(f"lane A membership audit failed for {family}/{severity}")
            by_cell[family][severity] = len(members)
    return {"status": "passed", "expected": len(expected), "packaged": sum(seen.values()), "by_family": by_cell,
            "suppressed": sum(1 for lead in expected.values() if lead.suppression_status == "suppressed"),
            "duplicates": sum(1 for lead in expected.values() if lead.duplicate_of),
            "kev_admitted": sum(1 for lead in expected.values()
                                if lead.kev_listed is True and lead.effective_severity not in admitted)}


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
                      cwe_reference: CweReference | None = None,
                      graph_settings: GraphSettings | None = None) -> Assembly:
    """Assemble both lanes and the package manifest; raises on any membership or integrity failure.

    ``cwe_reference`` is the run-pinned MITRE CWE catalog (``review.references``); without it,
    weakness names come from the accepted ``reference_intelligence`` facts or stay unresolved.
    """
    settings = settings or PackageSettings()
    collection = collection if collection is not None else collect_leads(scope)
    collection = LeadCollection(tuple(sorted(collection.leads, key=lambda lead: lead.observation_id)),
                                collection.gaps, collection.available, collection.correlation_audit,
                                collection.correlation_shards, collection.non_lead_counts)
    graph_settings = graph_settings if graph_settings is not None else run_graph_settings(scope.run_root)
    assembler = _Assembler(scope, settings, collection, cwe_reference, graph_settings)
    admitted = admitted_leads(collection, settings)
    admitted_ids = {lead.observation_id for lead in admitted}
    packages = [assembler.finding_lead(lead) for lead in admitted]
    lane_a = audit_membership(collection, packages, settings.admit_severities, settings.admit_kev,
                             settings.exploration_enabled, settings.exploration_reserve)

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
                                and lead.kev_listed is True
                                and lead.reported_severity not in settings.admit_severities) for family in FAMILIES}
    document: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA, "assembly_rule": ASSEMBLY_RULE, "package_schema": PACKAGE_SCHEMA,
        "run_id": scope.run_id, "manifest_sha256": scope.manifest_sha256, "target_snapshot": scope.target_snapshot,
        "settings": settings.record(), "graph_settings": asdict(graph_settings),
        "admission": [{"lead_id": lead.observation_id, "effective_severity": lead.effective_severity,
                       "status": "admitted" if lead.observation_id in admitted_ids else "not_admitted",
                       "reasons": admission_reasons(lead, settings),
                       "residual_coverage": "review_pending" if lead.observation_id in admitted_ids
                       else "exploration_reserve_cutoff" if admission_reasons(lead, settings)
                       else "outside_admission_policy"}
                      for lead in sorted(collection.leads, key=lambda item: item.observation_id)],
        "rules": {"families": dict(FAMILY_RULES), "rank": RANK_RULE, "obligations": OBLIGATION_RULE,
                  "neighborhood": NEIGHBORHOOD_RULE},
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
