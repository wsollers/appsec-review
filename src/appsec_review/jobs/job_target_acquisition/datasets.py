"""Dataset declarations for the pre-intake target-acquisition gate."""

from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_target_acquisition/attempts/*"
CONSUMES = ()
DATASETS = (
    artifact_only(
        "target_acquisition", "publication", "configuration", "appsec-review/target-acquisition-job/1",
        "Pinned acquisition or read-only re-verification of every component of the requested review system.",
        artifacts=(
            _A + "/steps/selection/tasks/resolve_system/target-acquisition-plan.json",
            _A + "/steps/acquisition/tasks/acquire_components/target-acquisition-result.json",
            _A + "/steps/acquisition/tasks/acquire_components/system-manifest.json",
            _A + "/steps/publication/tasks/publish_handoff/target-acquisition-handoff.json",
        ),
        reason="source provenance of the review target; intake binds the composed tree fingerprint",
    ),
)
