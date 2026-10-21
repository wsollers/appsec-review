"""Pluggable scoring providers for adjudicated claims.

Providers are built from a closed table keyed by implementation id; the scoring stage asks
:func:`registry_from_settings` for the enabled, implemented providers and scores each one with the
factors it declares. Adding a provider means a new entry in ``IMPLEMENTATIONS``; the stage is
unchanged.

``application_risk_matrix/3`` takes the ``scoring.cwe_impact_overrides`` table and the run's pinned
MITRE CWE catalog (:class:`~.cwe_impact.ImpactCatalog`) for its ``impact_class`` factor (decision
11). ``application_risk_matrix/1`` ignores both and rates its frozen legacy CWE table.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

from appsec_review.review.scoring.application_matrix import LEGACY_CWE_IMPACT_CLASSES, ApplicationRiskMatrixProvider
from appsec_review.review.scoring.application_matrix_v3 import ApplicationRiskMatrixV3Provider
from appsec_review.review.scoring.cwe_impact import (
    DERIVATION_RULE, UNAVAILABLE_CATALOG, ImpactCatalog, ImpactOverride,
)
from appsec_review.review.scoring.factors import FactorRegistry, default_factor_registry
from appsec_review.review.scoring.interface import (
    INTERFACE_VERSION, DimensionScore, ProviderRegistry, ScoreProviderResult, ScoreRequest, ScoringProvider,
    SeverityAssessment, UnavailableProvider, ValidationResult, consumed_factors,
)
from appsec_review.review.scoring.risk_model import DEFAULT_RISK_MODEL, RiskModel

DEFAULT_IMPLEMENTATION = "application_risk_matrix/3"

Builder = Callable[[Mapping[str, Any], "RiskModel | None", "ImpactCatalog | None"], ScoringProvider]


def _matrix_v1(_overrides: Mapping[str, Any], model: RiskModel | None,
               _catalog: ImpactCatalog | None) -> ScoringProvider:
    if model is not None:
        raise ValueError("application_risk_matrix/1 takes no risk model; use application_risk_matrix/3")
    return ApplicationRiskMatrixProvider(LEGACY_CWE_IMPACT_CLASSES)


def _matrix_v3(overrides: Mapping[str, Any], model: RiskModel | None,
               catalog: ImpactCatalog | None) -> ScoringProvider:
    return ApplicationRiskMatrixV3Provider(overrides, model or DEFAULT_RISK_MODEL, catalog)


# Closed table: implementation id -> (provider id, builder). /1 stays selectable for comparison and
# rollback; it ignores factors, overrides and the catalog and rates only its frozen CWE table and
# the claim state.
IMPLEMENTATIONS: Mapping[str, tuple[str, Builder]] = {
    "application_risk_matrix/1": ("application_risk_matrix", _matrix_v1),
    "application_risk_matrix/3": ("application_risk_matrix", _matrix_v3),
}


def build_provider(implementation: str, cwe_impact_overrides: Mapping[str, Any] | None = None,
                   model: RiskModel | None = None, catalog: ImpactCatalog | None = None) -> ScoringProvider:
    try:
        _, builder = IMPLEMENTATIONS[implementation]
    except KeyError as exc:
        raise ValueError(f"unknown scoring provider implementation: {implementation}") from exc
    return builder(cwe_impact_overrides or {}, model, catalog)


def default_registry(cwe_impact_overrides: Mapping[str, Any] | None = None, *,
                     implementation: str = DEFAULT_IMPLEMENTATION, model: RiskModel | None = None,
                     catalog: ImpactCatalog | None = None) -> ProviderRegistry:
    """A closed registry holding ``application_risk_matrix`` at ``implementation``."""
    return ProviderRegistry((build_provider(implementation, cwe_impact_overrides, model, catalog),))


def registry_from_settings(scoring: Any, catalog: ImpactCatalog | None = None) -> ProviderRegistry:
    """Registry of every enabled provider whose configured implementation exists here.

    ``scoring`` is ``config.inference_review.ScoringSettings``; ``catalog`` is the run's pinned CWE
    impact catalog (absent: ``impact_class`` is derived from nothing). An enabled provider with no
    implementation yet (``cvss_v4``, ``ssvc_decision``) is not registered and not skipped silently:
    it is listed in ``ProviderRegistry.unavailable``, and the scoring stage publishes it in the
    scores document and records one ``score_gap`` for it.
    """
    providers = []
    unavailable = []
    for name in scoring.enabled_providers:
        configured = scoring.providers.get(name)
        implementation = configured.implementation if configured is not None else (
            DEFAULT_IMPLEMENTATION if name == "application_risk_matrix" else None)
        if implementation in IMPLEMENTATIONS and IMPLEMENTATIONS[implementation][0] == name:
            providers.append(build_provider(implementation, scoring.cwe_impact_overrides,
                                            getattr(configured, "model", None), catalog))
        else:
            unavailable.append(UnavailableProvider(name, implementation, (
                f"scoring provider {name} is enabled but has no implementation in this build"
                + (f" ({implementation})" if implementation else "") + "; it produced no score")))
    return ProviderRegistry(tuple(providers), tuple(unavailable))


__all__ = [
    "DEFAULT_IMPLEMENTATION", "DERIVATION_RULE", "IMPLEMENTATIONS", "INTERFACE_VERSION", "LEGACY_CWE_IMPACT_CLASSES",
    "UNAVAILABLE_CATALOG", "ApplicationRiskMatrixProvider", "ApplicationRiskMatrixV3Provider", "DimensionScore",
    "FactorRegistry", "ImpactCatalog", "ImpactOverride", "ProviderRegistry", "RiskModel", "ScoreProviderResult",
    "ScoreRequest", "ScoringProvider", "SeverityAssessment", "UnavailableProvider", "ValidationResult", "build_provider", "consumed_factors",
    "default_factor_registry", "default_registry", "registry_from_settings",
]
