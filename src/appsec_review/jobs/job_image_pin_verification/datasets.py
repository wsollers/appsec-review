"""Dataset declarations for the pre-intake image-pin verification gate."""

from appsec_review.runtime.datasets import EvidenceAuthority
from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_image_pin_verification/attempts/*"
DATASETS = (
    artifact_only(
        "image_pin_verification", "publication", "configuration", "appsec-review/image-pin-verification/1",
        "Local resolution of every enabled catalog image and configured image-ID pin for one dispatch.",
        artifacts=(
            _A + "/steps/selection/tasks/resolve_pins/image-pin-plan.json",
            _A + "/steps/verification/tasks/inspect_images/image-pin-verification.json",
            _A + "/steps/publication/tasks/publish_handoff/image-pin-verification-handoff.json",
        ),
        reason="tool image pin provenance; no target security evidence", authority=EvidenceAuthority.OPERATIONAL,
    ),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
    ),
    schedule_after=('job_model_connectivity',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.NONE,
    always_execute=True,
    propagate_handoff=False,
)
CONSUMES = CONTRACT.consumes
