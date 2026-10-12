"""Pluggable scoring providers for adjudicated claims.

Providers are built from a closed table keyed by implementation id; the scoring stage asks
:func:`registry_from_settings` for the enabled, implemented providers and scores each one with the
factors it declares. Adding a provider means a new entry in ``IMPLEMENTATIONS``; the stage is
unchanged.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

from appsec_review.review.scoring.application_matrix import ApplicationRiskMatrixProvider
from appsec_review.review.scoring.application_matrix_v2 import ApplicationRiskMatrixV2Provider
from appsec_review.review.scoring.factors import FactorRegistry, default_factor_registry
from appsec_review.review.scoring.interface import (
    INTERFACE_VERSION, DimensionScore, ProviderRegistry, ScoreProviderResult, ScoreRequest, ScoringProvider,
    ValidationResult, consumed_factors,
)
from appsec_review.review.scoring.risk_model import DEFAULT_RISK_MODEL, RiskModel

DEFAULT_IMPLEMENTATION = "application_risk_matrix/2"


def _matrix_v1(cwe_impact_classes: Mapping[str, str], model: RiskModel | None) -> ScoringProvider:
    if model is not None:
        raise ValueError("application_risk_matrix/1 takes no risk model; use application_risk_matrix/2")
    return ApplicationRiskMatrixProvider(cwe_impact_classes)


def _matrix_v2(cwe_impact_classes: Mapping[str, str], model: RiskModel | None) -> ScoringProvider:
    return ApplicationRiskMatrixV2Provider(cwe_impact_classes, model or DEFAULT_RISK_MODEL)


# Closed table: implementation id -> (provider id, builder). /1 stays selectable for comparison and
# rollback; it ignores factors and rates only the CWE table and the claim state.
IMPLEMENTATIONS: Mapping[str, tuple[str, Callable[[Mapping[str, str], RiskModel | None], ScoringProvider]]] = {
    "application_risk_matrix/1": ("application_risk_matrix", _matrix_v1),
    "application_risk_matrix/2": ("application_risk_matrix", _matrix_v2),
}


def build_provider(implementation: str, cwe_impact_classes: Mapping[str, str],
                   model: RiskModel | None = None) -> ScoringProvider:
    try:
        _, builder = IMPLEMENTATIONS[implementation]
    except KeyError as exc:
        raise ValueError(f"unknown scoring provider implementation: {implementation}") from exc
    return builder(cwe_impact_classes, model)


def default_registry(cwe_impact_classes: Mapping[str, str], *, implementation: str = DEFAULT_IMPLEMENTATION,
                     model: RiskModel | None = None) -> ProviderRegistry:
    """A closed registry holding ``application_risk_matrix`` at ``implementation``."""
    return ProviderRegistry((build_provider(implementation, cwe_impact_classes, model),))


def registry_from_settings(scoring: Any) -> ProviderRegistry:
    """Registry of every enabled provider whose configured implementation exists here.

    ``scoring`` is ``config.inference_review.ScoringSettings``. An enabled provider with no
    implementation yet (``cvss_v4``, ``ssvc_decision``) is not registered; its absence is the
    documented slice state, not a per-claim gap.
    """
    providers = []
    for name in scoring.enabled_providers:
        configured = scoring.providers.get(name)
        implementation = configured.implementation if configured is not None else (
            DEFAULT_IMPLEMENTATION if name == "application_risk_matrix" else None)
        if implementation in IMPLEMENTATIONS and IMPLEMENTATIONS[implementation][0] == name:
            providers.append(build_provider(implementation, scoring.cwe_impact_classes,
                                            getattr(configured, "model", None)))
    return ProviderRegistry(tuple(providers))


__all__ = [
    "DEFAULT_IMPLEMENTATION", "IMPLEMENTATIONS", "INTERFACE_VERSION", "ApplicationRiskMatrixProvider",
    "ApplicationRiskMatrixV2Provider", "DimensionScore", "FactorRegistry", "ProviderRegistry", "RiskModel",
    "ScoreProviderResult", "ScoreRequest", "ScoringProvider", "ValidationResult", "build_provider", "consumed_factors",
    "default_factor_registry", "default_registry", "registry_from_settings",
]
