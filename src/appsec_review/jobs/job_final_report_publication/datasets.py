"""Dataset publication declarations for ``job_final_report_publication``."""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_final_report_publication/attempts/*"
# The report reads the accepted final publication gate handoff and the artifacts it binds, and the accepted
# proof-of-concept handoff when job_poc_generation ran (an inactive job is dropped from the consumed set).
DATASETS = (
    artifact_only(
        "final_report_publications", "acceptance", "inference_review", "appsec-review/final-report/2",
        "The machine-readable final report (final-report.json) and its deterministic Markdown rendering "
        "(final-report.md), hash-pinned by the accepted handoff.",
        artifacts=(_A + "/steps/load/**", _A + "/steps/report/**", _A + "/steps/acceptance/**"),
        reason="the report is the pipeline's terminal publication; indexing sanitized findings for retrieval "
               "and PDF rendering are later steps"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_final_publication_gate", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_final_publication_gate", "publication_gate_decisions",
                         "appsec-review/final-publication-gate/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    ),
    schedule_after=('job_final_publication_gate',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
