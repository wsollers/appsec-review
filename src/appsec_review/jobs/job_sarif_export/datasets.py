"""Dataset publication declarations and job contract for ``job_sarif_export``."""
from __future__ import annotations

from appsec_review.runtime.contracts import (
    Availability,
    DispatchClass,
    EvidenceAuthority,
    InputRequirement,
    JobContract,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.runtime.datasets import artifact_only

from .contracts import SARIF_EXPORT_RESULT_SCHEMA

_A = "data/jobs/job_sarif_export/attempts/*"

DATASETS = (
    artifact_only(
        "sarif_exports",
        "acceptance",
        "inference_review",
        SARIF_EXPORT_RESULT_SCHEMA,
        "Deterministic OASIS SARIF 2.1.0 security findings export with codeFlows, validated fixes, "
        "CWE/OWASP 2025 taxa, and 12-axis radar domain metadata.",
        artifacts=(_A + "/steps/export/**", _A + "/steps/acceptance/**"),
        reason="terminal IDE/CI interchange artifact derived from accepted gate findings",
    ),
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement(
            "job_final_publication_gate",
            "handoff",
            "appsec-review/job-handoff/2",
            authority=EvidenceAuthority.PRODUCER_EVIDENCE,
            availability=Availability.REQUIRED,
            missing=MissingPolicy.REJECT,
        ),
        InputRequirement(
            "job_final_publication_gate",
            "publication_gate_decisions",
            "appsec-review/final-publication-gate/2",
            authority=EvidenceAuthority.PRODUCER_EVIDENCE,
        ),
    ),
    schedule_after=("job_final_publication_gate",),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
