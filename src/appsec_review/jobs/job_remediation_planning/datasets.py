"""Protected attempt-owned proposals and source context, never a target mutation."""
from appsec_review.runtime.datasets import artifact_only, protected

_A = "data/jobs/job_remediation_planning/attempts/*/steps"
DATASETS = (
    artifact_only("remediation_planning_summary", "acceptance", "inference_review",
                  "appsec-review/remediation-planning/1", "Exact confirmed-only planning outcomes and gaps.",
                  artifacts=(_A + "/load/**", _A + "/acceptance/**"),
                  reason="downstream consumers use the accepted hash-bound summary"),
    protected("remediation_proposals", "assess", "inference_review", "appsec-review/remediation-plan/1",
              "Inert patches, regression specifications, resolving source context and model receipts.",
              artifacts=(_A + "/assess/**",),
              reason="source excerpts and untrusted model proposals are protected developer artifacts"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_inference_security_review", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_inference_security_review", "accepted_scope",
                         "appsec-review/inference-review-accepted-scope/1", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_inference_security_review", "lead_triage",
                         "application/json", authority=EvidenceAuthority.PROVISIONAL),
        InputRequirement("job_inference_security_review", "review_packages",
                         "appsec-review/review-package/6", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_inference_security_review", "review_cells",
                         "appsec-review/cell-attempt-receipt/1", authority=EvidenceAuthority.PROVISIONAL),
        InputRequirement("job_inference_security_review", "claim_ledger",
                         "appsec-review/ledger-event/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_inference_security_review", "attack_chains",
                         "appsec-review/attack-chain-manifest/1", authority=EvidenceAuthority.PROVISIONAL),
        InputRequirement("job_inference_security_review", "scores_and_findings",
                         "appsec-review/finding-package/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "topology_refinement_inputs",
                         "appsec-review/build-topology-refinement/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "build_actions",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "jvm_build_actions",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "language_build_receipts",
                         "appsec-review/language-build-handoff/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "build_workspaces",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    ),
    schedule_after=('job_inference_security_review', 'job_poc_generation'),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
