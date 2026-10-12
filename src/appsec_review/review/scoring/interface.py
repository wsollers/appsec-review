"""Versioned scoring provider boundary (design "Independent pluggable scoring").

Providers emit one normalized four-dimension package. Dimensions a provider does not produce stay
``None`` and are named in ``missing_factors``; unlike scales are never combined or coerced.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable

from appsec_review.review.evidence import make_gap
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import ClaimState, Gap, GapClass

INTERFACE_VERSION = "appsec-review/scoring-provider/1"
SCORE_PACKAGE_SCHEMA = "appsec-review/score-package/1"
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

    def canonical(self) -> dict[str, Any]:
        value = asdict(self)
        value["claim_state"] = ClaimState(self.claim_state).value
        value["evidence_relation_ids"] = sorted(set(self.evidence_relation_ids))
        return value

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
    schema: str = SCORE_PACKAGE_SCHEMA


@runtime_checkable
class ScoringProvider(Protocol):
    provider_id: str
    interface_version: str
    implementation_version: str

    def input_schema(self) -> Mapping[str, object]: ...
    def output_schema(self) -> Mapping[str, object]: ...
    def validate_inputs(self, request: ScoreRequest) -> ValidationResult: ...
    def score(self, request: ScoreRequest) -> ScoreProviderResult: ...


def input_fingerprint(provider: ScoringProvider, provider_config_sha256: str, request: ScoreRequest) -> str:
    return sha256_hex({"provider": provider.provider_id, "interface": provider.interface_version,
                       "implementation": provider.implementation_version,
                       "provider_config_sha256": provider_config_sha256, "request": request.canonical()})


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
