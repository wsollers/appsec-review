"""``application_risk_matrix/1``: the deterministic slice 1 scoring provider (design R8).

Axes are ``impact_class`` (from a configured CWE table, no parent roll-up) and
``exploitability_confidence`` (``high`` when confirmed, ``medium`` when supported). A claim that is
already ``supported`` or ``confirmed`` and whose lead advisory is CISA KEV-listed has its
exploitability confidence raised one band (``medium`` -> ``high``; ``high`` stays ``high``), recorded
as an assumption; KEV never makes an unsupported claim scoreable. NVD CVSS vectors and EPSS are
recorded as labelled reference inputs and do not change the band. The matrix band is reported as
technical severity on this provider's own scale; environmental impact and remediation priority are
not produced.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.review.claims import normalize_cwe
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import ClaimState
from appsec_review.review.scoring.interface import (
    EVIDENCE_CONFIDENCE_SCALE, INTERFACE_VERSION, SCOREABLE_STATES, DimensionScore, ScoreProviderResult,
    ScoreRequest, ValidationResult, input_fingerprint, score_identity,
)

PROVIDER_ID = "application_risk_matrix"
IMPLEMENTATION_VERSION = "application_risk_matrix/1"
IMPACT_CLASSES = ("low", "medium", "high", "critical")
CONFIDENCE_LEVELS = ("medium", "high")
BANDS = ("low", "medium", "high", "critical")
CONFIDENCE_BY_STATE = MappingProxyType({ClaimState.CONFIRMED: "high", ClaimState.SUPPORTED: "medium"})
DEFAULT_MATRIX: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "critical": MappingProxyType({"high": "critical", "medium": "high"}),
    "high": MappingProxyType({"high": "high", "medium": "medium"}),
    "medium": MappingProxyType({"high": "medium", "medium": "low"}),
    "low": MappingProxyType({"high": "low", "medium": "low"}),
})
UNPRODUCED_DIMENSIONS = ("environmental_business_impact", "remediation_priority")


class ApplicationRiskMatrixProvider:
    provider_id = PROVIDER_ID
    interface_version = INTERFACE_VERSION
    implementation_version = IMPLEMENTATION_VERSION

    def __init__(self, cwe_impact_classes: Mapping[str, str],
                 matrix: Mapping[str, Mapping[str, str]] = DEFAULT_MATRIX) -> None:
        table: dict[str, str] = {}
        for cwe, impact in cwe_impact_classes.items():
            normalized = normalize_cwe(cwe)
            if normalized is None or impact not in IMPACT_CLASSES:
                raise ValueError(f"invalid CWE impact class entry: {cwe}")
            if table.get(normalized, impact) != impact:
                raise ValueError(f"conflicting CWE impact class entries: {normalized}")
            table[normalized] = impact
        if set(matrix) != set(IMPACT_CLASSES) or any(
                set(row) != set(CONFIDENCE_LEVELS) or not set(row.values()) <= set(BANDS)
                for row in matrix.values()):
            raise ValueError("risk matrix must map every impact class and confidence level to a band")
        self._table = MappingProxyType(dict(sorted(table.items())))
        self._matrix = MappingProxyType({impact: MappingProxyType(dict(sorted(row.items())))
                                         for impact, row in sorted(matrix.items())})
        self.provider_config_sha256 = sha256_hex({
            "cwe_impact_classes": dict(self._table),
            "matrix": {impact: dict(row) for impact, row in self._matrix.items()},
        })

    def input_schema(self) -> Mapping[str, object]:
        return {"type": "object", "required": ["claim_state", "weakness_cwe"],
                "properties": {"claim_state": {"enum": sorted(state.value for state in SCOREABLE_STATES)},
                               "weakness_cwe": {"type": ["string", "null"], "pattern": "^CWE-[1-9][0-9]*$"}}}

    def output_schema(self) -> Mapping[str, object]:
        return {"axes": {"impact_class": list(IMPACT_CLASSES), "exploitability_confidence": list(CONFIDENCE_LEVELS)},
                "bands": list(BANDS), "technical_severity_scale": IMPLEMENTATION_VERSION,
                "exploitability_confidence_scale": EVIDENCE_CONFIDENCE_SCALE,
                "unproduced_dimensions": list(UNPRODUCED_DIMENSIONS)}

    def validate_inputs(self, request: ScoreRequest) -> ValidationResult:
        errors = []
        if ClaimState(request.claim_state) not in SCOREABLE_STATES:
            errors.append(f"claim state {ClaimState(request.claim_state).value} is not scored")
        if request.weakness_cwe is not None and normalize_cwe(request.weakness_cwe) != request.weakness_cwe:
            errors.append("weakness is not a canonical CWE id")
        return ValidationResult(not errors, tuple(errors))

    def score(self, request: ScoreRequest) -> ScoreProviderResult:
        validation = self.validate_inputs(request)
        if not validation.valid:
            raise ValueError("; ".join(validation.errors))
        confidence = CONFIDENCE_BY_STATE[ClaimState(request.claim_state)]
        assumptions: list[str] = []
        kev_raised = request.kev_listed is True and confidence != CONFIDENCE_LEVELS[-1]
        if kev_raised:
            confidence = CONFIDENCE_LEVELS[CONFIDENCE_LEVELS.index(confidence) + 1]
            assumptions.append("CISA KEV lists the lead advisory as exploited in the wild; exploitability "
                               "confidence raised one band for this already-supported claim")
        if request.reference_cvss:
            assumptions.append("NVD CVSS vectors recorded as reference inputs; they describe the advisory, not "
                               "this target, and do not set the band")
        if request.epss is not None:
            assumptions.append("FIRST EPSS recorded as a reference input; it does not set the band")
        impact = self._table.get(request.weakness_cwe) if request.weakness_cwe is not None else None
        band = self._matrix[impact][confidence] if impact is not None else None
        missing = ["weakness_cwe"] if request.weakness_cwe is None else (
            [] if impact is not None else ["impact_class"])
        native: dict[str, Any] = {
            "matrix": IMPLEMENTATION_VERSION,
            "axes": {"impact_class": impact, "exploitability_confidence": confidence},
            "cell": [impact, confidence] if impact is not None else None,
            "band": band,
            **({"kev_adjusted": True} if kev_raised else {}),
        }
        native_sha256 = sha256_hex(native)
        fingerprint = input_fingerprint(self, self.provider_config_sha256, request)
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
            exploitability_confidence=DimensionScore(EVIDENCE_CONFIDENCE_SCALE, confidence),
            environmental_business_impact=None, remediation_priority=None,
            evidence_relations=tuple(sorted(set(request.evidence_relation_ids))),
            missing_factors=tuple(sorted([*missing, *UNPRODUCED_DIMENSIONS])),
            assumptions=tuple(assumptions),
            reference_inputs=request.reference_inputs() if (request.reference_cvss or request.kev_listed is not None
                                                            or request.epss is not None) else {},
        )
