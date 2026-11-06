"""Dataset declarations for the pre-intake target-acquisition gate."""

from appsec_review.runtime.datasets import EvidenceAuthority
from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_target_acquisition/attempts/*"
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
        reason="source provenance of the review target; intake binds the composed tree fingerprint", authority=EvidenceAuthority.OPERATIONAL,
    ),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
    ),
    schedule_after=('job_image_pin_verification',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.NONE,
    always_execute=True,
    propagate_handoff=False,
)
CONSUMES = CONTRACT.consumes
