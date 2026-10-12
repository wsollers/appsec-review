"""Run-owned, pre-adjudication review package publication contract."""

from appsec_review.runtime.datasets import artifact_only

CONSUMES = ("job_review_data_indexing",)
DATASETS = (
    artifact_only(
        "review_packages", "publication", "precomputed", "appsec-review/review-package-manifest/2",
        "Hash-verified finding-lead, scanner-hunt, and document-hunt packages bound to the accepted retrieval manifest.",
        artifacts=("data/review-packages/*/*.json",),
        reason="bounded role-specific packages are consumed by identity, not indexed as general retrieval text",
    ),
)
