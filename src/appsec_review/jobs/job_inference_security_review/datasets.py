"""Dataset publication declarations for job_inference_security_review.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, protected


_J = "data/jobs/job_inference_security_review"
_A = _J + "/attempts/*"
# The single input is the accepted run/index manifest; its producer handoff is the data-indexing job.
CONSUMES = ("job_review_data_indexing",)
DATASETS = (
    artifact_only("review_packages", "packages", "inference_review", "appsec-review/review-package/2",
                  "Lane A finding-lead and lane B hunt packages with their verified package manifest.",
                  artifacts=(_A + "/steps/packages/**",),
                  reason="packages are run-owned review inputs bound to one accepted manifest; consumers read "
                         "the claim ledger and finding packages instead"),
    protected("review_cells", "lead_review", "inference_review", "appsec-review/cell-attempt-receipt/1",
              "Per-cell attempt receipts, verifier request checks and lane team documents (hashes and validated "
              "model results only; raw prompts are never stored).",
              artifacts=(_J + "/cells/**", _A + "/steps/lead_review/**", _A + "/steps/hunt_review/**",
                         _A + "/budget/**", _A + "/lanes/**", _J + "/review-teams/**"),
              reason="model results and retrieval transcripts are untrusted worker output kept for audit and "
                     "cell reuse only"),
    artifact_only("claim_ledger", "publication", "inference_review", "appsec-review/ledger-event/1",
                  "Hash-chained claim ledger shards, the merged canonical ledger, its head and projection.",
                  artifacts=(_A + "/steps/merge/**", _A + "/steps/adjudicate/**", _A + "/steps/completeness/**",
                             _A + "/steps/publication/tasks/publish_claim_ledger/**"),
                  reason="the claim ledger is the review's single authority record; a scoped finding query is "
                         "planned with final publication"),
    artifact_only("scores_and_findings", "publication", "inference_review", "appsec-review/finding-package/1",
                  "Independent score packages, confirmed/supported finding packages and the accepted handoff.",
                  artifacts=(_A + "/steps/scoring/**", _A + "/steps/publication/tasks/publish_handoff/**"),
                  reason="finding packages feed remediation and final publication jobs, which index sanitized "
                         "findings themselves"),
)
