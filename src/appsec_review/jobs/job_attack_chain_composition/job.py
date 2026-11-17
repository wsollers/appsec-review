"""Semantic job wrapper for multi-step attack chain composition (T-173)."""
from __future__ import annotations

from typing import Any, Mapping

from appsec_review.interchange import GapCode, ProducerStatus, producer_gap
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.runtime.contracts import JobContract, TargetAccess

from .composer import compose_multi_step_chains
from .contracts import AttackChainCompositionSettings, ChainStepFinding

JOB_ID = "job_attack_chain_composition"
SCHEMA = "appsec-review/attack-chain-composition/1"


def build_job() -> Job:
    """Build the standalone typed job contract with strict producer-gap/1 enforcement."""

    def compose_unit(unit: UnitContext) -> Mapping[str, Any]:
        raw = unit.job.config.settings if isinstance(unit.job.config.settings, Mapping) else {}
        cfg_keys = {
            "max_steps", "max_expansions", "max_candidates_per_composition",
            "admit_medium_cross_unit", "admit_medium_cross_boundary", "thinking_min_output_tokens",
        }
        settings = AttackChainCompositionSettings.from_mapping({k: v for k, v in raw.items() if k in cfg_keys})
        raw_findings = raw.get("findings", ())
        findings = [ChainStepFinding(**item) for item in raw_findings if isinstance(item, Mapping)]
        edges = raw.get("candidate_edges", ())
        report = compose_multi_step_chains(findings, edges, settings=settings)
        gaps = []
        if len(findings) < 2:
            gaps.append(producer_gap(
                GapCode.PRODUCER_REPORTED_GAP,
                "fewer_than_two_findings: multi-step chain composition requires at least two adjudicated findings",
                unit_id=unit.unit_id,
                scope_id="run",
            ))
        status = ProducerStatus.COMPLETED_WITH_GAPS.value if gaps else ProducerStatus.SUCCEEDED.value
        return {"schema": SCHEMA, **report.to_json(), "gaps": gaps, "terminal_status": status}

    units = (Unit("compose.multi_step_chains", compose_unit),)
    return Job(
        JOB_ID,
        "attack_chain_composition",
        UnitExecutor(units).execute,
        schema_identity=SCHEMA,
        units=units,
        strict_gaps=True,
        contract=JobContract(target_access=TargetAccess.ACCEPTED_EVIDENCE),
    )
