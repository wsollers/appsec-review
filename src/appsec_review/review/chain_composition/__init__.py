"""Multi-step cross-unit and cross-trust-boundary attack chain composition (T-173)."""
from .composer import (
    EVIDENCE_QUERYING_SKILL_ID,
    compose_multi_step_chains,
    evaluate_chain_elevation,
    load_chain_querying_skill,
)
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
    "EVIDENCE_QUERYING_SKILL_ID",
    "SEVERITY_RANK",
    "compose_multi_step_chains",
    "evaluate_chain_elevation",
    "load_chain_querying_skill",
    "max_severity",
]
