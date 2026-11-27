"""Dataset publication declarations for ``job_final_report_publication``.

``final_report_publications`` claims ``steps/report/tasks/render/**`` and
``steps/report/tasks/render_pdf/**``, covering both ``final-report.{md,html,tex,pdf}``
and the streamlined ``executive-report-candidate-{a,b,c}.{md,html,tex,pdf}`` artifacts
plus their hash-pinned receipts.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, protected
from appsec_review.jobs.engineering_contracts import FINAL_REPORT_SCHEMA


_A = "data/jobs/job_final_report_publication/attempts/*"
# The report reads the accepted final publication gate handoff and the artifacts it binds, and the accepted
# proof-of-concept handoff when job_poc_generation ran (an inactive job is dropped from the consumed set).
DATASETS = (
    artifact_only(
        "final_report_publications", "acceptance", "inference_review", FINAL_REPORT_SCHEMA,
        "The machine-readable final report (final-report.json), its deterministic Markdown rendering "
        "(final-report.md), HTML (final-report.html) and the executive PDF (final-report.tex, final-report.pdf, receipt.json and retained "
        "renderer logs), all hash-pinned by the accepted handoff.",
        artifacts=(_A + "/steps/load/**", _A + "/steps/report/tasks/assemble/final-report.json",
                   _A + "/steps/report/tasks/render/**", _A + "/steps/report/tasks/render_pdf/**",
                   _A + "/steps/acceptance/**"),
        reason="the report is the pipeline's terminal publication; indexing sanitized findings for retrieval "
               "is a later step"),
    protected(
        "final_report_sarif", "report", "inference_review", "application/sarif+json;version=2.1.0",
        "Gate-certified findings with explicit severity and dossier source locations.",
        artifacts=(_A + "/steps/report/tasks/assemble/findings.sarif",),
        reason="local vulnerability disclosure export; no external publication"),
    artifact_only(
        "final_report_sarif_accounting", "report", "inference_review", "appsec-review/sarif-export-result/1",
        "SARIF artifact identity, result counts and explicit omitted-record export gaps.",
        artifacts=(_A + "/steps/report/tasks/assemble/sarif-export-result.json",),
        reason="terminal export accounting"),
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
