"""Pluggable scoring providers for adjudicated claims."""
from __future__ import annotations

from typing import Mapping

from appsec_review.review.scoring.application_matrix import ApplicationRiskMatrixProvider
from appsec_review.review.scoring.interface import (
    INTERFACE_VERSION, DimensionScore, ProviderRegistry, ScoreProviderResult, ScoreRequest, ScoringProvider,
    ValidationResult,
)


def default_registry(cwe_impact_classes: Mapping[str, str]) -> ProviderRegistry:
    """Return the slice 1 closed registry holding ``application_risk_matrix/1``."""
    return ProviderRegistry((ApplicationRiskMatrixProvider(cwe_impact_classes),))


__all__ = [
    "INTERFACE_VERSION", "ApplicationRiskMatrixProvider", "DimensionScore", "ProviderRegistry",
    "ScoreProviderResult", "ScoreRequest", "ScoringProvider", "ValidationResult", "default_registry",
]
