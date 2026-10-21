"""Evidence-derived scoring factors (``score-factors/1``).

A factor is one closed-scale fact about an adjudicated claim, derived deterministically from what
adjudication already accepted: the claim's counted supporting relations (design R3/R5), the
entities those relations cite after the scoring stage re-resolves them against the accepted
manifest, accepted security-tag assignments on the affected entities or component, the claim's
CWE, and the labelled KEV reference input. Model prose, reported scanner severity and FIRST EPSS
never reach a factor: :class:`FactorInput` has no field for them.

Every factor either has a value on its closed, ordered scale (weakest first) with the citations
that produced it, or is listed as missing with a reason. Absent evidence is a missing factor, never
the lowest value, so a run without graph facts or tags is visibly less informed rather than scored
as low-risk. A factor never promotes a claim: only ``confirmed`` and ``supported`` claims are
scored, and factors are read from relations adjudication already counted.

Extraction is pluggable. :class:`FactorRegistry` maps a factor id to its extractor; scoring
providers declare the factor ids they consume (``consumed_factors``), and the scoring stage asks the
registry for exactly those. Adding a factor is a new :class:`FactorExtractor` registered in
:func:`default_factor_registry` plus its scale here; the stage does not change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

from appsec_review.graph.bounds import fact_bounds_destination, sink_destination_bytes
from appsec_review.graph.contract import ATTACKER_REACHABLE_SOURCES, Family, SourceClass
from appsec_review.review.scoring import cwe_impact
from appsec_review.review.models import ClaimState, EvidenceRelation, Predicate, RelationKind

FACTORS_VERSION = "score-factors/1"


class FactorId(StrEnum):
    VERIFICATION = "verification"
    TAINT_PATH = "taint_path"
    ATTACKER_CONTROL = "attacker_control"
    GUARD_ABSENT = "guard_absent"
    EXPOSURE = "exposure"
    PRIVILEGE = "privilege"
    DATA_SENSITIVITY = "data_sensitivity"
    IMPACT_CLASS = "impact_class"
    THREAT = "threat"


# Closed scales, weakest value first. A scale's order is what "stronger evidence" means for
# monotonicity: a model may never award fewer points to a later value than to an earlier one.
SCALES: Mapping[FactorId, tuple[str, ...]] = MappingProxyType({
    FactorId.VERIFICATION: ("supported", "confirmed"),
    FactorId.TAINT_PATH: ("code_evidence", "tool_observation", "codeql_path_observation", "graph_dataflow_path"),
    FactorId.ATTACKER_CONTROL: ("internal", "direct_unclassified", "local", "remote"),
    FactorId.GUARD_ABSENT: ("code_evidence", "tool_observation", "graph_fact"),
    FactorId.EXPOSURE: ("local", "internal_network", "public"),
    FactorId.PRIVILEGE: ("sandboxed", "elevated"),
    FactorId.DATA_SENSITIVITY: ("sensitive", "secret"),
    FactorId.IMPACT_CLASS: ("low", "medium", "high", "critical"),
    FactorId.THREAT: ("not_listed", "kev_listed"),
})

# Graph source classes (graph-catalog/1) mapped to attacker_control values. The attacker-reachable
# set is the shared contract's (user decision A2); remote is the strongest of them.
_LOCAL_SOURCES = frozenset(ATTACKER_REACHABLE_SOURCES - {SourceClass.REMOTE})
SOURCE_CLASS_VALUES: Mapping[str, str] = MappingProxyType({
    **{item.value: "local" for item in _LOCAL_SOURCES},
    SourceClass.REMOTE.value: "remote",
    SourceClass.DATABASE.value: "internal",
    SourceClass.INTERNAL.value: "internal",
})

# Accepted security-tag vocabulary (security-tag-taxonomy.md) mapped to factor values. Tags outside
# these maps (boundary tags, other namespaces) do not set a factor.
EXPOSURE_TAGS: Mapping[str, str] = MappingProxyType({
    "surface:entry:http-public": "public", "surface:entry:cloud-public": "public",
    "surface:entry:mobile-deeplink": "public", "surface:entry:ci-untrusted": "public",
    "surface:entry:http-internal": "internal_network", "surface:entry:rpc": "internal_network",
    "surface:entry:message-consumer": "internal_network",
    "surface:entry:cli": "local", "surface:entry:env-config": "local", "surface:entry:file-input": "local",
    "surface:entry:local-ipc": "local",
})
PRIVILEGE_TAGS: Mapping[str, str] = MappingProxyType({
    "surface:priv:elevated": "elevated", "surface:priv:host": "elevated", "surface:priv:cluster-admin": "elevated",
    "surface:priv:cloud-admin": "elevated", "surface:priv:ci-write": "elevated",
    "surface:priv:sandboxed": "sandboxed",
})
DATA_TAGS: Mapping[str, str] = MappingProxyType({
    "data:credential": "secret", "data:key-material": "secret", "data:session-token": "secret",
    "data:pii": "sensitive", "data:financial": "sensitive", "data:health": "sensitive",
})
# Tag bases the taxonomy allows for surface/data facts; ``reported`` and ``confirmed`` never apply.
TAG_BASES = frozenset({"declared", "invoked", "derived"})

TAGS_NOT_SUPPLIED = "accepted security tag assignments were not supplied to scoring"


class CitationKind(StrEnum):
    EVIDENCE_RELATION = "evidence_relation"
    ENTITY = "entity"
    TAG_ASSIGNMENT = "tag_assignment"
    ADJUDICATION = "adjudication"
    REFERENCE_INPUT = "reference_input"
    CONFIGURATION = "configuration"


@dataclass(frozen=True, slots=True, order=True)
class Citation:
    kind: CitationKind
    id: str

    def record(self) -> dict[str, str]:
        return {"kind": CitationKind(self.kind).value, "id": self.id}


@dataclass(frozen=True, slots=True)
class FactorValue:
    factor: FactorId
    value: str
    citations: tuple[Citation, ...]
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.value not in SCALES[FactorId(self.factor)]:
            raise ValueError(f"{self.factor} value {self.value!r} is not on its scale")
        if not self.citations:
            raise ValueError(f"{self.factor} has no citation")
        object.__setattr__(self, "citations", tuple(sorted(set(self.citations))))
        detail: dict[str, tuple[str, ...]] = {}
        for key, values in sorted(self.detail.items()):
            if isinstance(values, (str, bytes)) or not all(isinstance(item, str) for item in values):
                raise ValueError(f"{self.factor} detail {key} must be a list of strings")
            detail[str(key)] = tuple(sorted(set(values)))
        object.__setattr__(self, "detail", MappingProxyType(detail))

    @property
    def scale(self) -> str:
        return f"{FACTORS_VERSION}:{FactorId(self.factor).value}"

    @property
    def rank(self) -> int:
        """Position on the factor's scale; higher is stronger evidence."""
        return SCALES[FactorId(self.factor)].index(self.value)

    def record(self) -> dict[str, Any]:
        return {"factor": FactorId(self.factor).value, "scale": self.scale, "value": self.value,
                "detail": _jsonable(self.detail), "citations": [item.record() for item in self.citations]}


@dataclass(frozen=True, slots=True)
class MissingFactor:
    factor: FactorId
    reason: str

    def record(self) -> dict[str, str]:
        return {"factor": FactorId(self.factor).value, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class FactorSet:
    """The factors one provider consumes for one claim; canonical and order-independent."""

    values: tuple[FactorValue, ...]
    missing: tuple[MissingFactor, ...]
    version: str = FACTORS_VERSION

    def __post_init__(self) -> None:
        values = tuple(sorted(self.values, key=lambda item: FactorId(item.factor).value))
        missing = tuple(sorted(self.missing, key=lambda item: FactorId(item.factor).value))
        ids = [item.factor for item in values] + [item.factor for item in missing]
        if len(ids) != len(set(ids)):
            raise ValueError("a factor is both present and missing, or listed twice")
        object.__setattr__(self, "values", values)
        object.__setattr__(self, "missing", missing)

    def get(self, factor: FactorId | str) -> FactorValue | None:
        return next((item for item in self.values if item.factor == FactorId(factor)), None)

    @property
    def factor_ids(self) -> tuple[FactorId, ...]:
        return tuple(sorted({item.factor for item in self.values} | {item.factor for item in self.missing},
                            key=lambda item: item.value))

    def canonical(self) -> dict[str, Any]:
        return {"version": self.version, "values": [item.record() for item in self.values],
                "missing": [item.record() for item in self.missing]}


# ------------------------------------------------------------------------------------------------
# Inputs


@dataclass(frozen=True, slots=True)
class ResolvedEntity:
    """An entity the scoring stage re-resolved against the accepted manifest, content-verified."""

    entity_id: str
    kind: str
    payload: Mapping[str, Any]
    path: str | None = None
    component_id: str | None = None


@dataclass(frozen=True, slots=True)
class TagAssignment:
    """One accepted security-tag assignment that applies to the claim, and how it was matched."""

    assignment_id: str            # the tag_assignment entity identity
    tag: str
    basis: str
    match: str                    # "entity" (subject is an anchor) or "component" (anchor's component)


@dataclass(frozen=True, slots=True)
class FactorInput:
    """Everything factors may read for one claim. EPSS, reported severity and prose are absent."""

    claim_id: str
    adjudication_id: str
    claim_state: ClaimState
    weakness_cwe: str | None
    supporting: tuple[EvidenceRelation, ...]           # counted SUPPORTS relations, per adjudication
    entities: Mapping[str, ResolvedEntity] = field(default_factory=dict)
    unresolved: tuple[str, ...] = ()                    # cited entities that did not re-resolve
    tags: tuple[TagAssignment, ...] | None = None       # None: no accepted tag assignments supplied
    tags_unavailable_reason: str = TAGS_NOT_SUPPLIED
    kev_listed: bool | None = None

    def supporting_for(self, predicate: Predicate) -> tuple[EvidenceRelation, ...]:
        return tuple(item for item in self.supporting
                     if item.predicate is predicate and item.kind is RelationKind.SUPPORTS)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def locator_path(locator: str) -> str | None:
    """The source path of an ``evidence.py`` location locator (``path:l-l#bS-E@sha``), else ``None``."""
    head, separator, tail = locator.rpartition(":")
    return head if separator and head and "#b" in tail and "@" in tail else None


def factor_input(*, claim_id: str, adjudication_id: str, claim_state: ClaimState, weakness_cwe: str | None,
                 affected_entities: Iterable[str], predicates: Iterable[Mapping[str, Any]],
                 relations: Iterable[EvidenceRelation], source: "EvidenceSource | None" = None,
                 kev_listed: bool | None = None) -> FactorInput:
    """Build a claim's :class:`FactorInput` from its adjudication record and projected relations.

    Only relations the adjudication counted as supporting enter. ``source`` re-resolves their cited
    entities and supplies accepted tag assignments; without one, payload- and tag-derived factors
    are missing with a reason.
    """
    counted = {relation for item in predicates for relation in item.get("supporting", ())}
    supporting = tuple(sorted((item for item in relations if item.relation_id in counted
                               and item.kind is RelationKind.SUPPORTS), key=lambda item: item.relation_id))
    if {item.relation_id for item in supporting} != counted:
        raise ValueError("adjudication counts a supporting relation the projection does not hold")
    entities: dict[str, ResolvedEntity] = {}
    unresolved: set[str] = set()
    tags: tuple[TagAssignment, ...] | None = None
    reason = TAGS_NOT_SUPPLIED
    if source is not None:
        for relation in supporting:
            if relation.entity_id in entities:
                continue
            resolved = source.resolve(relation)
            if resolved is None:
                unresolved.add(relation.entity_id)
            else:
                entities[relation.entity_id] = resolved
        anchors = set(affected_entities) | {item.entity_id for item in supporting}
        paths = {path for item in supporting if (path := locator_path(item.locator))}
        paths |= {item.path for item in entities.values() if item.path}
        tags = source.tags(anchors, paths, {item.component_id for item in entities.values() if item.component_id})
        reason = source.tags_unavailable_reason
    return FactorInput(claim_id=claim_id, adjudication_id=adjudication_id, claim_state=ClaimState(claim_state),
                       weakness_cwe=weakness_cwe, supporting=supporting,
                       entities=MappingProxyType(dict(sorted(entities.items()))), unresolved=tuple(sorted(unresolved)),
                       tags=tags, tags_unavailable_reason=reason, kev_listed=kev_listed)


@runtime_checkable
class EvidenceSource(Protocol):
    """Re-resolves cited entities and supplies accepted tag assignments for the scoring stage."""

    tags_unavailable_reason: str

    def resolve(self, relation: EvidenceRelation) -> ResolvedEntity | None: ...
    def tags(self, anchors: set[str], paths: set[str], components: set[str]) -> tuple[TagAssignment, ...] | None: ...


# ------------------------------------------------------------------------------------------------
# Extractors


class FactorExtractor(Protocol):
    factor: FactorId

    def extract(self, data: FactorInput) -> FactorValue | MissingFactor: ...


def _relation_citations(relations: Iterable[EvidenceRelation]) -> list[Citation]:
    found: list[Citation] = []
    for relation in relations:
        found.append(Citation(CitationKind.EVIDENCE_RELATION, relation.relation_id))
        found.append(Citation(CitationKind.ENTITY, relation.entity_id))
    return found


def _best(factor: FactorId, candidates: Iterable[tuple[str, EvidenceRelation | TagAssignment, Mapping[str, Any]]],
          missing: str) -> FactorValue | MissingFactor:
    """The strongest value wins; its citations are every candidate that produced that value."""
    scale = SCALES[factor]
    items = list(candidates)
    if not items:
        return MissingFactor(factor, missing)
    best = max(scale.index(value) for value, _, _ in items)
    winners = [(source, detail) for value, source, detail in items if scale.index(value) == best]
    citations: list[Citation] = []
    details: dict[str, set[str]] = {}
    for source, detail in winners:
        if isinstance(source, TagAssignment):
            citations.append(Citation(CitationKind.TAG_ASSIGNMENT, source.assignment_id))
        else:
            citations.extend(_relation_citations((source,)))
        for key, value in detail.items():
            details.setdefault(key, set()).add(str(value))
    return FactorValue(factor, scale[best], tuple(citations),
                       {key: sorted(values) for key, values in sorted(details.items())})


class VerificationExtractor:
    factor = FactorId.VERIFICATION

    def extract(self, data: FactorInput) -> FactorValue | MissingFactor:
        state = ClaimState(data.claim_state)
        if state not in (ClaimState.CONFIRMED, ClaimState.SUPPORTED):
            return MissingFactor(self.factor, f"claim state {state.value} is not scored")
        return FactorValue(self.factor, state.value, (Citation(CitationKind.ADJUDICATION, data.adjudication_id),))


def _is_codeql_path(entity: ResolvedEntity | None) -> bool:
    if entity is None:
        return False
    payload = entity.payload
    if str(payload.get("producer") or "").lower() != "codeql":
        return False
    rule = payload.get("rule") if isinstance(payload.get("rule"), Mapping) else {}
    properties = rule.get("properties") if isinstance(rule.get("properties"), Mapping) else {}
    return "path-problem" in {payload.get("query_kind"), properties.get("kind"), payload.get("kind")}


def _direct_eligible(entity: ResolvedEntity | None) -> bool:
    admissibility = entity.payload.get("admissibility") if entity is not None else None
    return isinstance(admissibility, Mapping) and admissibility.get("direct_eligible") is True


class TaintPathExtractor:
    """Direct support on ``source_to_sink_reachability``; the basis is the strongest cited kind.

    The kind comes from the counted relation, which validation derived from the re-resolved entity;
    telling a CodeQL path observation from another tool observation needs the re-resolved payload,
    and without it the weaker ``tool_observation`` basis is used.
    """

    factor = FactorId.TAINT_PATH

    def extract(self, data: FactorInput) -> FactorValue | MissingFactor:
        candidates = []
        for relation in data.supporting_for(Predicate.SOURCE_TO_SINK_REACHABILITY):
            if relation.entity_kind == Family.DATAFLOW_PATH.value:
                basis = "graph_dataflow_path"
            elif relation.entity_kind == "tool_observation":
                entity = data.entities.get(relation.entity_id)
                basis = "codeql_path_observation" if _is_codeql_path(entity) else "tool_observation"
            else:
                basis = "code_evidence"
            candidates.append((basis, relation, {"entity_kind": relation.entity_kind}))
        return _best(self.factor, candidates, "no counted direct support on source_to_sink_reachability")


class AttackerControlExtractor:
    """Source class of cited graph entry points and paths; best class wins.

    A re-resolved, direct-eligible ``entry_point`` or ``dataflow_path`` gives its source class.
    Other counted direct support on ``attacker_input_control`` (a source span, a mapped tool
    observation) shows control without a class: ``direct_unclassified``.
    """

    factor = FactorId.ATTACKER_CONTROL

    def extract(self, data: FactorInput) -> FactorValue | MissingFactor:
        candidates = []
        relevant = (data.supporting_for(Predicate.ATTACKER_INPUT_CONTROL)
                    + data.supporting_for(Predicate.SOURCE_TO_SINK_REACHABILITY))
        for relation in relevant:
            entity = data.entities.get(relation.entity_id)
            source_class = None
            if relation.entity_kind in (Family.ENTRY_POINT.value, Family.DATAFLOW_PATH.value) and _direct_eligible(
                    entity):
                result = entity.payload.get("result") if isinstance(entity.payload.get("result"), Mapping) else {}
                if relation.entity_kind == Family.DATAFLOW_PATH.value:
                    result = result.get("source") if isinstance(result.get("source"), Mapping) else {}
                source_class = result.get("source_class")
            if source_class in SOURCE_CLASS_VALUES:
                candidates.append((SOURCE_CLASS_VALUES[source_class], relation, {"source_class": source_class}))
            elif relation.predicate is Predicate.ATTACKER_INPUT_CONTROL:
                candidates.append(("direct_unclassified", relation, {}))
        return _best(self.factor, candidates,
                     "no counted direct support on attacker_input_control and no classified cited source")


def _effective_guard(data: FactorInput, relation: EvidenceRelation) -> bool:
    """Whether the cited, re-resolved guard or range fact is shown to bound its destination.

    Uses the same pure helper as the evidence mapping (``graph.bounds``, ``evidence-admissibility/3``). A dominating
    guard that is not shown to bound the destination is not an effective guard, so citing it is still support that
    the guard is missing or ineffective. A range fact needs the destination size, which it takes from a guard fact
    of the same sink among the resolved entities; without one the range is not shown to bound.
    """
    entity = data.entities.get(relation.entity_id)
    if entity is None or relation.entity_kind not in (Family.GUARD_FACT.value, Family.RANGE_FACT.value):
        return False
    result = entity.payload.get("result") if isinstance(entity.payload.get("result"), Mapping) else {}
    sink = result.get("sink") if isinstance(result.get("sink"), Mapping) else {}
    destination = None
    if relation.entity_kind == Family.RANGE_FACT.value:
        destination = sink_destination_bytes(
            [other.payload["result"] for other in data.entities.values()
             if other.kind == Family.GUARD_FACT.value and isinstance(other.payload.get("result"), Mapping)
             and isinstance(other.payload["result"].get("sink"), Mapping)
             and other.payload["result"]["sink"].get("sink_site") == sink.get("sink_site")])
    return fact_bounds_destination(relation.entity_kind, result, destination).bounds


class GuardAbsentExtractor:
    """Direct support on ``missing_or_ineffective_guard``; the basis is the strongest cited kind.

    A supporting citation of a guard or range fact that the exported facts show bounds the destination is an
    effective guard and does not count as support that the guard is absent.
    """

    factor = FactorId.GUARD_ABSENT

    def extract(self, data: FactorInput) -> FactorValue | MissingFactor:
        candidates = []
        for relation in data.supporting_for(Predicate.MISSING_OR_INEFFECTIVE_GUARD):
            if _effective_guard(data, relation):
                continue
            if relation.entity_kind in (Family.GUARD_FACT.value, Family.RANGE_FACT.value):
                basis = "graph_fact"
            elif relation.entity_kind == "tool_observation":
                basis = "tool_observation"
            else:
                basis = "code_evidence"
            candidates.append((basis, relation, {"entity_kind": relation.entity_kind}))
        return _best(self.factor, candidates, "no counted direct support on missing_or_ineffective_guard")


class TagExtractor:
    """A factor read from accepted security-tag assignments on the claim's entities or component."""

    def __init__(self, factor: FactorId, tags: Mapping[str, str], description: str) -> None:
        if not set(tags.values()) <= set(SCALES[factor]):
            raise ValueError(f"{factor} tag map uses values outside its scale")
        self.factor = factor
        self._tags = tags
        self._description = description

    def extract(self, data: FactorInput) -> FactorValue | MissingFactor:
        if data.tags is None:
            return MissingFactor(self.factor, data.tags_unavailable_reason)
        candidates = [(self._tags[item.tag], item, {"tag": item.tag, "match": item.match})
                      for item in data.tags if item.tag in self._tags and item.basis in TAG_BASES]
        return _best(self.factor, candidates,
                     f"no accepted {self._description} tag on the affected entities or component")


class ImpactClassExtractor:
    """The CWE impact class (decision 11): one factor among many, never the whole score.

    Precedence is an override from ``scoring.cwe_impact_overrides``, then derivation from the run's
    pinned MITRE catalog under ``cwe-impact-derivation/1`` (:mod:`.cwe_impact`), then a missing
    factor with its reason. An override cites its configuration key; a derived class cites the
    catalog consequence entries that produced it.
    """

    factor = FactorId.IMPACT_CLASS

    def __init__(self, cwe_impact_overrides: Mapping[str, Any] | None = None,
                 catalog: cwe_impact.ImpactCatalog | None = None) -> None:
        self.overrides = cwe_impact.overrides_table(cwe_impact_overrides or {})
        self.catalog = catalog if catalog is not None else cwe_impact.UNAVAILABLE_CATALOG
        if not isinstance(self.catalog, cwe_impact.ImpactCatalog):
            raise TypeError("impact_class needs an ImpactCatalog")

    def identity(self) -> dict[str, Any]:
        """Everything the factor's value depends on besides the claim: enters the provider config hash."""
        return {"rule": cwe_impact.DERIVATION_RULE,
                "overrides": {cwe: item.document() for cwe, item in self.overrides.items()},
                "catalog": self.catalog.identity()}

    def extract(self, data: FactorInput) -> FactorValue | MissingFactor:
        return self.extract_cwe(data.weakness_cwe)

    def extract_cwe(self, cwe: str | None) -> FactorValue | MissingFactor:
        if cwe is None:
            return MissingFactor(self.factor, "claim has no weakness CWE")
        catalog = self.catalog
        derived, reason = self._derive(cwe)
        catalog_detail: dict[str, list[str]] = {}
        if catalog.status != "unavailable":
            catalog_detail = {"catalog_snapshot": [str(catalog.snapshot_id)], "catalog_status": [catalog.status]}
            if catalog.gap:
                catalog_detail["catalog_gap"] = [catalog.gap[:200]]
        override = self.overrides.get(cwe)
        if override is not None:
            detail = {"cwe": [cwe], "basis": ["override"], "rule": [cwe_impact.DERIVATION_RULE], **catalog_detail}
            if override.reason:
                detail["override_reason"] = [override.reason]
            if derived is not None:
                detail["derived_class"] = [derived.impact_class]
            return FactorValue(self.factor, override.impact_class,
                               (Citation(CitationKind.CONFIGURATION, f"{cwe_impact.OVERRIDE_KEY}.{cwe}"),), detail)
        if derived is None:
            return MissingFactor(self.factor, reason)
        detail = {"cwe": [cwe], "basis": ["derived"], "rule": [cwe_impact.DERIVATION_RULE],
                  "technical_impacts": list(derived.impacts), "scopes": list(derived.scopes), **catalog_detail}
        if derived.integrity_raised:
            detail["integrity_raised"] = ["read impact raised to high: the weakness is also integrity-scoped"]
        return FactorValue(self.factor, derived.impact_class,
                           tuple(Citation(CitationKind.REFERENCE_INPUT,
                                          cwe_impact.consequence_reference(catalog, cwe, item))
                                 for item in derived.consequences), detail)

    def _derive(self, cwe: str) -> tuple[cwe_impact.Derivation | None, str]:
        catalog = self.catalog
        if catalog.status == "unavailable":
            return None, f"impact_class not derived: {catalog.gap}"[:400]
        consequences = catalog.consequences.get(cwe)
        if consequences is None:
            return None, (f"{cwe} is not a weakness in the pinned MITRE CWE catalog {catalog.snapshot_id} and "
                          f"has no {cwe_impact.OVERRIDE_KEY} entry")
        if not consequences:
            return None, (f"{cwe} has no Common_Consequences in the pinned MITRE CWE catalog {catalog.snapshot_id} "
                          f"and no {cwe_impact.OVERRIDE_KEY} entry")
        derived = cwe_impact.derive(consequences)
        if derived is None:
            impacts = sorted({impact for item in consequences for impact in item.impacts})
            return None, (f"no technical impact of {cwe} ({', '.join(impacts)[:200] or 'none'}) is mapped by "
                          f"{cwe_impact.DERIVATION_RULE}, and it has no {cwe_impact.OVERRIDE_KEY} entry")
        return derived, ""


class ThreatExtractor:
    """CISA KEV listing of the claim's lead advisory. EPSS is deliberately not a threat factor."""

    factor = FactorId.THREAT

    def extract(self, data: FactorInput) -> FactorValue | MissingFactor:
        if data.kev_listed is None:
            return MissingFactor(self.factor, "no CISA KEV reference input for this claim")
        return FactorValue(self.factor, "kev_listed" if data.kev_listed else "not_listed",
                           (Citation(CitationKind.REFERENCE_INPUT, "kev_listed"),))


class FactorRegistry:
    """Closed registry of factor extractors keyed by factor id; no dynamic import."""

    def __init__(self, extractors: Iterable[FactorExtractor] = ()) -> None:
        self._extractors: dict[FactorId, FactorExtractor] = {}
        for extractor in extractors:
            self.register(extractor)

    def register(self, extractor: FactorExtractor) -> None:
        factor = FactorId(extractor.factor)
        if factor in self._extractors:
            raise ValueError(f"factor extractor already registered: {factor.value}")
        self._extractors[factor] = extractor

    def ids(self) -> tuple[FactorId, ...]:
        return tuple(sorted(self._extractors, key=lambda item: item.value))

    def extract(self, data: FactorInput, factors: Iterable[FactorId | str]) -> FactorSet:
        values: list[FactorValue] = []
        missing: list[MissingFactor] = []
        for factor in sorted({FactorId(item) for item in factors}, key=lambda item: item.value):
            extractor = self._extractors.get(factor)
            if extractor is None:
                missing.append(MissingFactor(factor, "no extractor is registered for this factor"))
                continue
            outcome = extractor.extract(data)
            if outcome.factor != factor:
                raise ValueError(f"extractor for {factor.value} returned {outcome.factor}")
            (values if isinstance(outcome, FactorValue) else missing).append(outcome)
        return FactorSet(tuple(values), tuple(missing))


def default_factor_registry(cwe_impact_overrides: Mapping[str, Any] | None = None,
                            catalog: "cwe_impact.ImpactCatalog | None" = None) -> FactorRegistry:
    """Every factor extractor; ``impact_class`` uses the overrides and the run's pinned CWE catalog."""
    return FactorRegistry((
        VerificationExtractor(), TaintPathExtractor(), AttackerControlExtractor(), GuardAbsentExtractor(),
        TagExtractor(FactorId.EXPOSURE, EXPOSURE_TAGS, "surface:entry"),
        TagExtractor(FactorId.PRIVILEGE, PRIVILEGE_TAGS, "surface:priv"),
        TagExtractor(FactorId.DATA_SENSITIVITY, DATA_TAGS, "data"),
        ImpactClassExtractor(cwe_impact_overrides, catalog), ThreatExtractor(),
    ))


__all__ = [
    "DATA_TAGS", "EXPOSURE_TAGS", "FACTORS_VERSION", "PRIVILEGE_TAGS", "SCALES", "SOURCE_CLASS_VALUES",
    "Citation", "CitationKind", "EvidenceSource", "FactorExtractor", "FactorId", "FactorInput", "FactorRegistry",
    "FactorSet", "FactorValue", "MissingFactor", "ResolvedEntity", "TagAssignment", "default_factor_registry",
    "factor_input", "locator_path",
]
