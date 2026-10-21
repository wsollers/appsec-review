"""Dataset publication declarations for ``job_final_report_publication``."""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_final_report_publication/attempts/*"
# The report reads the accepted final publication gate handoff and the artifacts it binds, and the accepted
# proof-of-concept handoff when job_poc_generation ran (an inactive job is dropped from the consumed set).
CONSUMES = ("job_final_publication_gate", "job_poc_generation")
DATASETS = (
    artifact_only(
        "final_report_publications", "acceptance", "inference_review", "appsec-review/final-report/1",
        "The machine-readable final report (final-report.json) and its deterministic Markdown rendering "
        "(final-report.md), hash-pinned by the accepted handoff.",
        artifacts=(_A + "/steps/load/**", _A + "/steps/report/**", _A + "/steps/acceptance/**"),
        reason="the report is the pipeline's terminal publication; indexing sanitized findings for retrieval "
               "and PDF rendering are later steps"),
)
