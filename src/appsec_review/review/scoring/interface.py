"""Versioned scoring provider boundary (design "Independent pluggable scoring").

Providers emit one normalized four-dimension package. Dimensions a provider does not produce stay
``None`` and are named in ``missing_factors``; unlike scales are never combined or coerced.

A provider may declare ``consumed_factors`` (``score-factors/1`` ids); the scoring stage then
extracts exactly those factors from the adjudicated evidence and passes them in
``ScoreRequest.factors``. A request without factors canonicalizes exactly as before, so providers
that consume none keep their fingerprints.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
import json
from typing import Any, Collection, Mapping, Protocol, runtime_checkable

from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import ClaimState, Gap, GapClass, make_gap
from appsec_review.review.scoring.factors import FactorId, FactorSet

INTERFACE_VERSION = "appsec-review/scoring-provider/1"
SCORE_PACKAGE_SCHEMA = "appsec-review/score-package/2"
EVIDENCE_CONFIDENCE_SCALE = "evidence_confidence/1"
SCOREABLE_STATES = frozenset({ClaimState.CONFIRMED, ClaimState.SUPPORTED})


@dataclass(frozen=True, slots=True)
class ScoreRequest:
    """Binds everything a score depends on; its fingerprint changes with any input."""

    claim_id: str
    adjudication_id: str
    claim_state: ClaimState
    weakness_cwe: str | None
    evidence_relation_ids: tuple[str, ...]
    environment_sha256: str | None
    policy_sha256: str
    scorer_actor_id: str
    # Labelled reference inputs from pinned feeds (NVD CVSS vectors, CISA KEV, FIRST EPSS). They describe
    # the advisory a lead came from, not the target; providers record them and may use them only as
    # documented (application_risk_matrix: KEV raises exploitability confidence one band). EPSS is
    # never a scoring input: the scoring stage does not pass it, and application_risk_matrix/2
    # excludes it from its fingerprint and package.
    reference_cvss: tuple[Mapping[str, Any], ...] = ()
    kev_listed: bool | None = None
    epss: Mapping[str, Any] | None = None
    # score-factors/1 values the provider declared it consumes, derived from adjudicated evidence.
    factors: FactorSet | None = None

    def canonical(self, exclude: Collection[str] = ()) -> dict[str, Any]:
        value: dict[str, Any] = {item.name: getattr(self, item.name) for item in fields(self)
                                 if item.name != "factors"}
        value["claim_state"] = ClaimState(self.claim_state).value
        value["evidence_relation_ids"] = sorted(set(self.evidence_relation_ids))
        # Absent reference inputs leave the canonical request (and every fingerprint) unchanged.
        value["reference_cvss"] = sorted((dict(item) for item in self.reference_cvss),
                                         key=lambda item: json.dumps(item, sort_keys=True, default=str))
        value["epss"] = dict(self.epss) if self.epss is not None else None
        for key, empty in (("reference_cvss", []), ("kev_listed", None), ("epss", None)):
            if value[key] == empty:
                del value[key]
        if self.factors is not None:
            value["factors"] = self.factors.canonical()
        for key in exclude:
            value.pop(key, None)
        return value

    def reference_inputs(self, exclude: Collection[str] = ()) -> dict[str, Any]:
        canonical = self.canonical()
        return {"label": "reference_context", "reference_cvss": canonical.get("reference_cvss", []),
                "kev_listed": self.kev_listed, "epss": None if "epss" in exclude else canonical.get("epss")}

    @property
    def fingerprint(self) -> str:
        return sha256_hex(self.canonical())


@dataclass(frozen=True, slots=True)
class ValidationResult:
    valid: bool
    errors: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class DimensionScore:
    scale: str
    rating: str | None
    value: float | None = None


@dataclass(frozen=True, slots=True)
class ScoreProviderResult:
    score_id: str
    claim_id: str
    adjudication_id: str
    scorer_actor_id: str
    provider_id: str
    interface_version: str
    implementation_version: str
    provider_config_sha256: str
    policy_sha256: str
    input_fingerprint: str
    native: Mapping[str, Any]
    native_sha256: str
    technical_severity: DimensionScore | None
    exploitability_confidence: DimensionScore | None
    environmental_business_impact: DimensionScore | None
    remediation_priority: DimensionScore | None
    evidence_relations: tuple[str, ...]
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    missing_factors: tuple[str, ...] = field(default_factory=tuple)
    overrides: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    reference_inputs: Mapping[str, Any] = field(default_factory=dict)
    schema: str = SCORE_PACKAGE_SCHEMA
    # The score-factors/1 values the provider used (with their citations) and why each consumed
    # factor is missing; ``None`` for providers that consume no factors.
    factors: FactorSet | None = None
    missing_factor_reasons: tuple[tuple[str, str], ...] = field(default_factory=tuple)


@runtime_checkable
class ScoringProvider(Protocol):
    provider_id: str
    interface_version: str
    implementation_version: str

    def input_schema(self) -> Mapping[str, object]: ...
    def output_schema(self) -> Mapping[str, object]: ...
    def validate_inputs(self, request: ScoreRequest) -> ValidationResult: ...
    def score(self, request: ScoreRequest) -> ScoreProviderResult: ...


def input_fingerprint(provider: ScoringProvider, provider_config_sha256: str, request: ScoreRequest,
                      exclude: Collection[str] = ()) -> str:
    """Fingerprint of everything a score depends on; ``exclude`` names request fields the provider
    provably ignores (``application_risk_matrix/2`` excludes ``epss``)."""
    return sha256_hex({"provider": provider.provider_id, "interface": provider.interface_version,
                       "implementation": provider.implementation_version,
                       "provider_config_sha256": provider_config_sha256, "request": request.canonical(exclude)})


def consumed_factors(provider: ScoringProvider) -> frozenset[FactorId]:
    """Factor ids a provider declares it consumes; a provider without the attribute consumes none."""
    return frozenset(FactorId(item) for item in getattr(provider, "consumed_factors", ()))


def score_identity(*, provider_id: str, implementation_version: str, provider_config_sha256: str,
                   input_fingerprint: str, native_sha256: str) -> str:
    return make_id("score", 1, {
        "provider": provider_id, "interface": INTERFACE_VERSION, "implementation": implementation_version,
        "provider_config_sha256": provider_config_sha256, "input_fingerprint": input_fingerprint,
        "native_sha256": native_sha256,
    })


class ProviderRegistry:
    """Closed registry of scoring providers keyed by ``provider_id``; no dynamic import."""

    def __init__(self, providers: tuple[ScoringProvider, ...] = ()) -> None:
        self._providers: dict[str, ScoringProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: ScoringProvider) -> None:
        if not isinstance(provider, ScoringProvider):
            raise TypeError("scoring provider does not implement the protocol")
        if provider.interface_version != INTERFACE_VERSION:
            raise ValueError("scoring provider interface version is unsupported")
        if provider.provider_id in self._providers:
            raise ValueError(f"scoring provider already registered: {provider.provider_id}")
        self._providers[provider.provider_id] = provider

    def get(self, provider_id: str) -> ScoringProvider:
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise KeyError(f"unknown scoring provider: {provider_id}") from exc

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    def score(self, provider_id: str, request: ScoreRequest, *, round: int = 0) -> ScoreProviderResult | Gap:
        """Score through ``provider_id``; an unavailable provider or invalid input is a ``score_gap``."""
        provider = self._providers.get(provider_id)
        if provider is None:
            return make_gap(GapClass.SCORE_GAP, request.claim_id, f"scoring provider unavailable: {provider_id}",
                            round=round)
        validation = provider.validate_inputs(request)
        if not validation.valid:
            return make_gap(GapClass.SCORE_GAP, request.claim_id,
                            f"{provider_id}: " + "; ".join(validation.errors), round=round)
        return provider.score(request)
