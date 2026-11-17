"""Semantic job wrapper for finding adjudication chain-severity preservation (T-173)."""
from __future__ import annotations

from typing import Any, Mapping

from appsec_review.interchange import GapCode, ProducerStatus, producer_gap
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.runtime.contracts import JobContract, TargetAccess

from .adjudicator import resolve_finding_chain_severity
from .contracts import FindingAdjudicationSettings

JOB_ID = "job_finding_adjudication"
SCHEMA = "appsec-review/finding-adjudication/1"


def build_job() -> Job:
    """Build the standalone typed job contract with strict producer-gap/1 enforcement."""

    def adjudicate_unit(unit: UnitContext) -> Mapping[str, Any]:
        raw = unit.job.config.settings if isinstance(unit.job.config.settings, Mapping) else {}
        settings = FindingAdjudicationSettings.from_mapping({
            k: v for k, v in raw.items() if k in {"preserve_chain_elevated_severity", "thinking_min_output_tokens"}
        })
        findings = raw.get("findings", ())
        chains = raw.get("chains", ())
        resolved = [
            resolve_finding_chain_severity(
                str(item["claim_id"]), standalone_severity=item.get("standalone_severity"),
                chain_records=chains, settings=settings,
            ).to_json()
            for item in findings if isinstance(item, Mapping) and item.get("claim_id")
        ]
        gaps = []
        if not resolved:
            gaps.append(producer_gap(
                GapCode.PRODUCER_REPORTED_GAP,
                "no_findings_supplied: no adjudicated findings supplied for chain-severity preservation",
                unit_id=unit.unit_id,
                scope_id="run",
            ))
        status = ProducerStatus.COMPLETED_WITH_GAPS.value if gaps else ProducerStatus.SUCCEEDED.value
        return {
            "schema": SCHEMA,
            "findings": resolved,
            "chain_elevated_count": sum(1 for item in resolved if item["chain_elevated"]),
            "gaps": gaps,
            "terminal_status": status,
        }

    units = (Unit("adjudicate.preserve_chain_severity", adjudicate_unit),)
    return Job(
        JOB_ID,
        "finding_adjudication",
        UnitExecutor(units).execute,
        schema_identity=SCHEMA,
        units=units,
        strict_gaps=True,
        contract=JobContract(target_access=TargetAccess.ACCEPTED_EVIDENCE),
    )
