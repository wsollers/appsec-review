"""Dataset publication declarations and input contract for ``job_detailed_finding_report``."""
from __future__ import annotations

from appsec_review.jobs.engineering_contracts import DETAILED_FINDING_REPORT_SCHEMA
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

_A = "data/jobs/job_detailed_finding_report/attempts/*"

DATASETS = (
    artifact_only(
        "detailed_finding_reports",
        "acceptance",
        "inference_review",
        DETAILED_FINDING_REPORT_SCHEMA,
        "The machine-readable detailed finding report (detailed-finding-report.json), its deterministic Markdown "
        "(detailed-finding-report.md), HTML (detailed-finding-report.html), standalone 3a/3b/3c SVG/Mermaid/DOT "
        "diagrams, and vector LaTeX/PDF (detailed-finding-report.tex, detailed-finding-report.pdf, receipt.json "
        "and retained renderer logs), all hash-pinned by the accepted handoff.",
        artifacts=(
            _A + "/steps/load/**",
            _A + "/steps/report/tasks/assemble/**",
            _A + "/steps/report/tasks/render/**",
            _A + "/steps/report/tasks/render_pdf/**",
            _A + "/steps/acceptance/**",
        ),
        reason="terminal visual defect report pairing each gate-certified finding with 3a taint, 3b call-fanout and 3c CFG diagrams",
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
        InputRequirement(
            "job_code_graph_index",
            "handoff",
            "appsec-review/job-handoff/2",
            authority=EvidenceAuthority.PRODUCER_EVIDENCE,
            availability=Availability.OPTIONAL,
            missing=MissingPolicy.GAP,
        ),
        InputRequirement(
            "job_code_graph_index",
            "alternate_cpg",
            "appsec-review/alternate-cpg/1",
            authority=EvidenceAuthority.PRODUCER_EVIDENCE,
            availability=Availability.OPTIONAL,
            missing=MissingPolicy.GAP,
        ),
    ),
    schedule_after=("job_final_report_publication",),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
    always_execute=False,
    propagate_handoff=True,
)

CONSUMES = CONTRACT.consumes
