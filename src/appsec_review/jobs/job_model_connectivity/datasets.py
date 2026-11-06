"""Dataset declarations for the mandatory live model-connectivity gate."""

from appsec_review.runtime.datasets import EvidenceAuthority
from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_model_connectivity/attempts/*"
DATASETS = (
    artifact_only(
        "model_connectivity", "publication", "configuration", "appsec-review/model-preflight/1",
        "Fresh provider and model connectivity evidence for one graph dispatch.",
        artifacts=(
            _A + "/steps/connectivity/tasks/verify_models/model-connectivity.json",
            _A + "/steps/publication/tasks/publish_handoff/model-connectivity-handoff.json",
        ),
        reason="live provider readiness metadata; no target security evidence", authority=EvidenceAuthority.OPERATIONAL,
    ),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
    ),
    schedule_after=(),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.NONE,
    always_execute=True,
    propagate_handoff=False,
)
CONSUMES = CONTRACT.consumes
