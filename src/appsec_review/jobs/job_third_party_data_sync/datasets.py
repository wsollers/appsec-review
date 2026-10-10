"""Dataset publication declarations for job_third_party_data_sync.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_third_party_data_sync/attempts/*"
CONSUMES = ()
DATASETS = (
    protected("feed_sync_work", "nvd_sync", "reference_feeds", "appsec-review/job-result/third-party-data-sync/1",
              "Feed download, normalization and database-build working files of a sync attempt.",
              artifacts=(_A + "/steps/*/tasks/*/work/**",),
              reason="bulky upstream feed archives and builder logs; published snapshots are pinned per run by "
                     "the review-data indexing job"),
)
