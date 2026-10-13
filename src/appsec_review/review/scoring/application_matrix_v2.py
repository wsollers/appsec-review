"""``application_risk_matrix/2``: evidence-driven, configurable application risk scoring.

The provider consumes ``score-factors/1`` values (see :mod:`.factors`) and rates them with the
declarative :class:`~.risk_model.RiskModel` from TOML:

- ``exploitability_confidence`` (scale ``exploitability_evidence/1``): summed factor points against
  the exploitability bands. A KEV-listed lead advisory raises an already scored claim one band
  (``low`` -> ``medium`` -> ``high``), recorded as an assumption; it never makes a claim scoreable.
- ``technical_severity`` (scale ``application_risk_matrix/2``): impact class x exploitability rating.
  ``impact_class`` is an override or is derived from the run's pinned MITRE CWE catalog under
  ``cwe-impact-derivation/1`` (:mod:`.cwe_impact`); when it is missing (no CWE, no catalog, no
  mapped consequence) technical severity is ``null``.
- ``environmental_business_impact`` (scale ``environmental_exposure/1``): exposure, privilege and
  data-sensitivity points, produced only when at least one of them is present.
- ``remediation_priority`` is never produced: no priority policy implementation is registered.

FIRST EPSS is not an input: it is excluded from the input fingerprint and from the package's
reference inputs, so varying it cannot change any byte of a score package. NVD CVSS vectors are
recorded as labelled reference inputs and do not set any band.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.review.claims import normalize_cwe
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import ClaimState
from appsec_review.review.scoring.cwe_impact import ImpactCatalog
from appsec_review.review.scoring.factors import FACTORS_VERSION, FactorId, ImpactClassExtractor
from appsec_review.review.scoring.interface import (
    INTERFACE_VERSION, SCOREABLE_STATES, DimensionScore, ScoreProviderResult, ScoreRequest, ValidationResult,
    input_fingerprint, score_identity,
)
from appsec_review.review.scoring.risk_model import BANDS, DEFAULT_RISK_MODEL, RATINGS, RiskModel

PROVIDER_ID = "application_risk_matrix"
IMPLEMENTATION_VERSION = "application_risk_matrix/2"
EXPLOITABILITY_SCALE = "exploitability_evidence/1"
ENVIRONMENTAL_SCALE = "environmental_exposure/1"
EXCLUDED_INPUTS = ("epss",)
NO_PRIORITY_POLICY = "no remediation priority policy implementation is registered"


class ApplicationRiskMatrixV2Provider:
    provider_id = PROVIDER_ID
    interface_version = INTERFACE_VERSION
    implementation_version = IMPLEMENTATION_VERSION

    def __init__(self, cwe_impact_overrides: Mapping[str, Any] | None = None,
                 model: RiskModel = DEFAULT_RISK_MODEL, catalog: ImpactCatalog | None = None) -> None:
        if not isinstance(model, RiskModel):
            raise TypeError("application_risk_matrix/2 needs a RiskModel")
        self._impact = ImpactClassExtractor(cwe_impact_overrides, catalog)
        self.model = model
        self.consumed_factors: frozenset[FactorId] = model.consumed_factors
        # The derivation rule, the overrides and the pinned catalog's snapshot identity enter the
        # configuration hash, so a new catalog, rule or override gives new score ids.
        self.provider_config_sha256 = sha256_hex({
            "factors": FACTORS_VERSION, "impact_class": self._impact.identity(), "model": model.document(),
        })

    @property
    def cwe_impact_overrides(self) -> Mapping[str, Any]:
        return self._impact.overrides

    @property
    def impact_catalog(self) -> ImpactCatalog:
        return self._impact.catalog

    def input_schema(self) -> Mapping[str, object]:
        return {"type": "object", "required": ["claim_state", "weakness_cwe", "factors"],
                "properties": {"claim_state": {"enum": sorted(state.value for state in SCOREABLE_STATES)},
                               "weakness_cwe": {"type": ["string", "null"], "pattern": "^CWE-[1-9][0-9]*$"},
                               "factors": {"version": FACTORS_VERSION,
                                           "consumed": sorted(item.value for item in self.consumed_factors)}},
                "excluded": list(EXCLUDED_INPUTS)}

    def output_schema(self) -> Mapping[str, object]:
        return {"bands": list(BANDS), "technical_severity_scale": IMPLEMENTATION_VERSION,
                "exploitability_confidence_scale": EXPLOITABILITY_SCALE, "exploitability_ratings": list(RATINGS),
                "environmental_business_impact_scale": ENVIRONMENTAL_SCALE, "environmental_ratings": list(RATINGS),
                "unproduced_dimensions": ["remediation_priority"]}

    def validate_inputs(self, request: ScoreRequest) -> ValidationResult:
        errors = []
        state = ClaimState(request.claim_state)
        if state not in SCOREABLE_STATES:
            errors.append(f"claim state {state.value} is not scored")
        if request.weakness_cwe is not None and normalize_cwe(request.weakness_cwe) != request.weakness_cwe:
            errors.append("weakness is not a canonical CWE id")
        factors = request.factors
        if factors is None:
            errors.append(f"{IMPLEMENTATION_VERSION} needs the {FACTORS_VERSION} factors it consumes")
        else:
            if factors.version != FACTORS_VERSION:
                errors.append(f"factor set version {factors.version} is not {FACTORS_VERSION}")
            if set(factors.factor_ids) != set(self.consumed_factors):
                errors.append("factor set does not hold exactly the consumed factors")
            verification = factors.get(FactorId.VERIFICATION)
            if verification is not None and verification.value != state.value:
                errors.append("verification factor disagrees with the claim state")
            impact = factors.get(FactorId.IMPACT_CLASS)
            if impact is not None and self._impact.extract_cwe(request.weakness_cwe) != impact:
                errors.append("impact_class factor disagrees with this provider's overrides and pinned CWE catalog")
        return ValidationResult(not errors, tuple(errors))

    def score(self, request: ScoreRequest) -> ScoreProviderResult:
        validation = self.validate_inputs(request)
        if not validation.valid:
            raise ValueError("; ".join(validation.errors))
        factors = request.factors
        assert factors is not None
        assumptions = ["a missing factor contributes no points; it is a named gap, not evidence of low risk"]
        rating, points, contributions = self.model.exploitability.rate(factors)
        threat = factors.get(FactorId.THREAT)
        kev_raised = threat is not None and threat.value == "kev_listed" and rating != RATINGS[-1]
        if kev_raised:
            rating = RATINGS[RATINGS.index(rating) + 1]
            assumptions.append("CISA KEV lists the lead advisory as exploited in the wild; exploitability "
                               "confidence raised one band for this already-supported claim")
        if request.reference_cvss:
            assumptions.append("NVD CVSS vectors recorded as reference inputs; they describe the advisory, not "
                               "this target, and do not set any band")
        impact = factors.get(FactorId.IMPACT_CLASS)
        if impact is not None and "stale" in impact.detail.get("catalog_status", ()):
            assumptions.append(f"impact_class was read from a stale pinned MITRE CWE catalog "
                               f"({self._impact.catalog.snapshot_id}); the stale gap is recorded on the factor")
        band = self.model.technical_severity[impact.value][rating] if impact is not None else None
        environmental: dict[str, Any] | None = None
        if self.model.environmental.present(factors):
            env_rating, env_points, env_contributions = self.model.environmental.rate(factors)
            environmental = {"rating": env_rating, "points": env_points, "contributions": env_contributions}
        reasons: dict[str, str] = {item.factor.value: item.reason for item in factors.missing}
        if band is None:
            reasons.setdefault("technical_severity", "impact_class is missing")
        if environmental is None:
            reasons["environmental_business_impact"] = ("no exposure, privilege or data sensitivity factor is "
                                                        "present")
        reasons["remediation_priority"] = NO_PRIORITY_POLICY
        native: dict[str, Any] = {
            "matrix": IMPLEMENTATION_VERSION, "factors": FACTORS_VERSION,
            "axes": {"impact_class": impact.value if impact is not None else None, "exploitability": rating},
            "cell": [impact.value, rating] if impact is not None else None,
            "band": band,
            "exploitability": {"rating": rating, "points": points, "contributions": contributions,
                               "kev_adjusted": kev_raised},
            "environmental": environmental,
        }
        native_sha256 = sha256_hex(native)
        fingerprint = input_fingerprint(self, self.provider_config_sha256, request, EXCLUDED_INPUTS)
        return ScoreProviderResult(
            score_id=score_identity(provider_id=self.provider_id, implementation_version=self.implementation_version,
                                    provider_config_sha256=self.provider_config_sha256,
                                    input_fingerprint=fingerprint, native_sha256=native_sha256),
            claim_id=request.claim_id, adjudication_id=request.adjudication_id,
            scorer_actor_id=request.scorer_actor_id, provider_id=self.provider_id,
            interface_version=self.interface_version, implementation_version=self.implementation_version,
            provider_config_sha256=self.provider_config_sha256, policy_sha256=request.policy_sha256,
            input_fingerprint=fingerprint, native=MappingProxyType(native), native_sha256=native_sha256,
            technical_severity=DimensionScore(IMPLEMENTATION_VERSION, band),
            exploitability_confidence=DimensionScore(EXPLOITABILITY_SCALE, rating, points),
            environmental_business_impact=(DimensionScore(ENVIRONMENTAL_SCALE, environmental["rating"],
                                                          environmental["points"])
                                           if environmental is not None else None),
            remediation_priority=None,
            evidence_relations=tuple(sorted(set(request.evidence_relation_ids))),
            missing_factors=tuple(sorted(reasons)),
            assumptions=tuple(assumptions),
            reference_inputs=(request.reference_inputs(EXCLUDED_INPUTS)
                              if request.reference_cvss or request.kev_listed is not None else {}),
            factors=factors,
            missing_factor_reasons=tuple(sorted(reasons.items())),
        )


__all__ = ["ApplicationRiskMatrixV2Provider", "ENVIRONMENTAL_SCALE", "EXPLOITABILITY_SCALE", "IMPLEMENTATION_VERSION"]
