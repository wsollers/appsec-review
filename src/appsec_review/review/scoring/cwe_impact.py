"""CWE impact class from the run-pinned MITRE catalog (``cwe-impact-derivation/1``, decision 11).

The ``application_risk_matrix/2`` ``impact_class`` factor is derived from the weakness's catalog
Common_Consequences (scopes and technical impacts) captured by ``mitre_sync`` and read from the
run's pinned ``index/mitre.sqlite`` (:mod:`appsec_review.review.references`). Precedence:

1. an explicit override (``scoring.cwe_impact_overrides``) for a documented exception;
2. derivation from the pinned catalog under :data:`DERIVATION_RULE`;
3. otherwise a missing factor with its reason, never a low value.

Each technical impact maps to a class (:data:`IMPACT_RULES`). A read impact (memory, application
data, files) is ``medium``, raised to ``high`` when the weakness also has an ``Integrity``-scoped
consequence whose impacts are not all rated ``low``. An Integrity scope with only ``Unexpected
State`` or quality impacts does not raise it; one with ``Other`` or ``Varies by Context`` does. The highest class over every consequence wins; impacts the rule does not
map (``Varies by Context``, ``Other``, unknown strings) contribute nothing, and a weakness with no
mapped impact leaves the factor missing.

Catalog states follow the stale-MITRE fallback for claim CWE validation (decision 5): an unpinned,
mismatched or unreadable catalog, or one without indexed consequences, derives nothing. A stale
catalog still derives (its consequences are reference data, as its names and abstractions remain),
and every factor derived from it records the stale gap in its detail.

Changing a mapping here is a new rule version; the rule id, the override table and the catalog
snapshot identity all enter the provider configuration hash.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.review.claims import normalize_cwe
from appsec_review.review.references import CweConsequence, CweReference

DERIVATION_RULE = "cwe-impact-derivation/1"
IMPACT_CLASSES = ("low", "medium", "high", "critical")       # weakest first, as the factor scale
OVERRIDE_KEY = "cwe_impact_overrides"
INTEGRITY_SCOPE = "integrity"
MAX_REASON_CHARS = 200

# MITRE CWE technical impacts (Common_Consequences/Impact), matched case-insensitively.
IMPACT_RULES: Mapping[str, str] = MappingProxyType({
    "execute unauthorized code or commands": "critical",
    "modify memory": "high",
    "gain privileges or assume identity": "high",
    "bypass protection mechanism": "high",
    "modify application data": "high",
    "modify files or directories": "high",
    "read memory": "medium",
    "read application data": "medium",
    "read files or directories": "medium",
    "alter execution logic": "medium",
    "dos: crash, exit, or restart": "medium",
    "dos: instability": "medium",
    "dos: amplification": "medium",
    "dos: resource consumption (cpu)": "medium",
    "dos: resource consumption (memory)": "medium",
    "dos: resource consumption (other)": "medium",
    "hide activities": "low",
    "unexpected state": "low",
    "quality degradation": "low",
    "reduce performance": "low",
    "reduce reliability": "low",
    "reduce maintainability": "low",
})
# Read impacts are raised to ``high`` when the weakness also has an Integrity-scoped consequence
# whose impacts are not all rated low.
READ_IMPACTS = frozenset({"read memory", "read application data", "read files or directories"})


@dataclass(frozen=True, slots=True)
class ImpactOverride:
    """An explicit exception to derivation, with the reason it exists."""

    impact_class: str
    reason: str = ""

    def __post_init__(self) -> None:
        if self.impact_class not in IMPACT_CLASSES:
            raise ValueError(f"impact class must be one of: {', '.join(IMPACT_CLASSES)}")
        object.__setattr__(self, "reason", " ".join(str(self.reason).split())[:MAX_REASON_CHARS])

    def document(self) -> dict[str, str]:
        return {"impact_class": self.impact_class, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class ImpactCatalog:
    """The run's pinned CWE consequences as scoring sees them, with their identity and state."""

    status: str                                   # "current" | "stale" | "unavailable"
    consequences: Mapping[str, tuple[CweConsequence, ...]] = field(default_factory=dict)
    snapshot_id: str | None = None
    manifest_sha256: str | None = None
    version: str | None = None
    gap: str | None = None

    def __post_init__(self) -> None:
        if self.status not in ("current", "stale", "unavailable"):
            raise ValueError(f"unknown impact catalog status: {self.status}")
        if self.status != "unavailable" and not self.snapshot_id:
            raise ValueError("an available impact catalog needs its snapshot id")
        if self.status != "current" and not self.gap:
            raise ValueError("a stale or unavailable impact catalog needs its gap")
        object.__setattr__(self, "consequences", MappingProxyType(dict(sorted(self.consequences.items()))))

    @classmethod
    def from_reference(cls, reference: CweReference) -> "ImpactCatalog":
        """The impact view of a :class:`CweReference`, following its pin state."""
        identity = {"snapshot_id": reference.snapshot_id, "manifest_sha256": reference.manifest_sha256,
                    "version": reference.version}
        if reference.source == "mitre_catalog":
            status, gap = "current", None
        elif reference.stale and reference.entries:
            status, gap = "stale", reference.gap or "mitre_stale_feed"
        else:
            return cls("unavailable", gap=reference.gap or "mitre_feed_unavailable", **identity)
        if not reference.consequences_indexed:
            return cls("unavailable", gap="mitre_consequences_unavailable: the pinned MITRE index predates "
                                          "mitre-index/2 and records no CWE Common_Consequences", **identity)
        return cls(status, {cwe: entry.consequences for cwe, entry in reference.entries.items()},
                   gap=gap, **identity)

    def identity(self) -> dict[str, Any]:
        """What enters the provider configuration hash: the snapshot identity and state, not the rows
        (the snapshot id and manifest hash already bind every row)."""
        return {"status": self.status, "snapshot_id": self.snapshot_id, "manifest_sha256": self.manifest_sha256,
                "version": self.version, "gap": self.gap}


UNAVAILABLE_CATALOG = ImpactCatalog("unavailable", gap="mitre_feed_unavailable: no pinned MITRE CWE catalog was "
                                                       "supplied to scoring")


@dataclass(frozen=True, slots=True)
class Derivation:
    impact_class: str
    consequences: tuple[CweConsequence, ...]       # every consequence that produced the winning class
    impacts: tuple[str, ...]
    scopes: tuple[str, ...]
    integrity_raised: bool


def derive(consequences: tuple[CweConsequence, ...]) -> Derivation | None:
    """Apply :data:`DERIVATION_RULE`; ``None`` when no consequence has a mapped technical impact."""
    integrity = [item for item in consequences
                 if any(scope.strip().casefold() == INTEGRITY_SCOPE for scope in item.scopes)
                 and not all(IMPACT_RULES.get(" ".join(impact.split()).casefold()) == "low"
                             for impact in item.impacts)]
    scored: list[tuple[int, CweConsequence, str, bool]] = []
    for consequence in consequences:
        for impact in consequence.impacts:
            key = " ".join(impact.split()).casefold()
            value = IMPACT_RULES.get(key)
            if value is None:
                continue
            raised = key in READ_IMPACTS and bool(integrity)
            scored.append((IMPACT_CLASSES.index("high" if raised else value), consequence, impact, raised))
    if not scored:
        return None
    best = max(item[0] for item in scored)
    winners = [item for item in scored if item[0] == best]
    raised = any(item[3] for item in winners)
    cited = {item[1].ordinal: item[1] for item in winners}
    if raised:
        cited.update({item.ordinal: item for item in integrity})
    chosen = tuple(cited[key] for key in sorted(cited))
    return Derivation(IMPACT_CLASSES[best], chosen, tuple(sorted({item[2] for item in winners})),
                      tuple(sorted({scope for item in chosen for scope in item.scopes})), raised)


def overrides_table(value: Mapping[str, ImpactOverride | str]) -> Mapping[str, ImpactOverride]:
    """Canonical override table keyed by normalized CWE id; a plain string is a class without reason."""
    table: dict[str, ImpactOverride] = {}
    for cwe, entry in value.items():
        normalized = normalize_cwe(cwe)
        override = entry if isinstance(entry, ImpactOverride) else ImpactOverride(str(entry))
        if normalized is None:
            raise ValueError(f"invalid CWE impact override entry: {cwe}")
        if normalized in table and table[normalized] != override:
            raise ValueError(f"conflicting CWE impact override entries: {normalized}")
        table[normalized] = override
    return MappingProxyType(dict(sorted(table.items())))


def consequence_reference(catalog: ImpactCatalog, cwe: str, consequence: CweConsequence) -> str:
    """Citation id of one catalog consequence entry: ``mitre-cwe:<snapshot>:<CWE>:consequence/<n>``."""
    return f"mitre-cwe:{catalog.snapshot_id}:{cwe}:consequence/{consequence.ordinal}"


__all__ = [
    "DERIVATION_RULE", "IMPACT_RULES", "OVERRIDE_KEY", "READ_IMPACTS", "UNAVAILABLE_CATALOG", "Derivation",
    "ImpactCatalog", "ImpactOverride", "consequence_reference", "derive", "overrides_table",
]
