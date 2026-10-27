"""Run-owned document candidate ledger; no unreviewed claim is indexed as a finding."""

from appsec_review.runtime.datasets import artifact_only

CONSUMES = ("job_review_package_assembly",)
DATASETS = (
    artifact_only("document_issue_ledger", "analysis", "documents",
                  "appsec-review/document-issue-ledger/1",
                  "Verified document hunts, source mappings, candidates, gaps, and supported findings.",
                  artifacts=("data/document-issues/*/ledger.json",
                             "data/jobs/job_document_issue_analysis/attempts/*/shared/document-issues/*.json"),
                  reason="private pre-adjudication claims are not general retrieval text"),
)
