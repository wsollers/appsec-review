"""Dataset publication declarations for job_review_intake.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_review_intake/attempts/*"
CONSUMES = ()
DATASETS = (
    artifact_only("model_preflight", "model_preflight", "configuration", "appsec-review/model-preflight/1",
                  "Provider and model availability report for configured model settings.",
                  artifacts=(_A + "/steps/model_preflight/tasks/verify_models/model-preflight.json",),
                  reason="provider status only; enabled lanes are reported through the dataset inventory"),
    artifact_only("review_intake", "publish_intake", "configuration", "appsec-review/review-intake/1",
                  "Bound configuration, target identity and source fingerprint for the run.",
                  artifacts=(_A + "/steps/publish_intake/tasks/publish_handoff/review-intake.json",),
                  reason="run binding record with host paths; its snapshot and hashes are inventory metadata"),
)
