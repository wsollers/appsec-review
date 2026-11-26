"""Multi-step cross-unit and cross-trust-boundary attack chain contracts (T-173)."""
from .contracts import (
    AttackChainCompositionSettings,
    BoundaryCrossing,
    ChainCompositionReport,
    ChainStepFinding,
    ComposedAttackChain,
    DEFAULT_MAX_CHAIN_STEPS,
    DEFAULT_MAX_STEPS,
    SEVERITY_RANK,
    max_severity,
)

__all__ = [
    "AttackChainCompositionSettings",
    "BoundaryCrossing",
    "ChainCompositionReport",
    "ChainStepFinding",
    "ComposedAttackChain",
    "DEFAULT_MAX_CHAIN_STEPS",
    "DEFAULT_MAX_STEPS",
    "SEVERITY_RANK",
    "max_severity",
]
