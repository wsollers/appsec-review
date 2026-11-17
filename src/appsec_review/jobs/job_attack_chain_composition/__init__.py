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
    THINKING_MIN_OUTPUT_TOKENS,
    max_severity,
)
from .job import JOB_ID, build_job

__all__ = [
    "AttackChainCompositionSettings",
    "BoundaryCrossing",
    "ChainCompositionReport",
    "ChainStepFinding",
    "ComposedAttackChain",
    "DEFAULT_MAX_CHAIN_STEPS",
    "DEFAULT_MAX_STEPS",
    "EVIDENCE_QUERYING_SKILL_ID",
    "JOB_ID",
    "SEVERITY_RANK",
    "THINKING_MIN_OUTPUT_TOKENS",
    "build_job",
    "compose_multi_step_chains",
    "evaluate_chain_elevation",
    "load_chain_querying_skill",
    "max_severity",
]
