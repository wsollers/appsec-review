"""Dataset publication declarations for ``job_final_publication_gate``."""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_final_publication_gate/attempts/*"
# The gate reads only the accepted inference review handoff and the artifacts it binds.
DATASETS = (
    artifact_only(
        "publication_gate_decisions", "acceptance", "inference_review",
        "appsec-review/final-publication-gate/2",
        "Hash-bound gate document: every finding package classified as publishable, verification backlog "
        "or withheld with exact accounting, the limitations list and the bindings re-verified from bytes.",
        artifacts=(_A + "/steps/load/**", _A + "/steps/gate/**", _A + "/steps/acceptance/**"),
        reason="the gate projects accepted review state and is read by the final report job; a scoped "
               "finding query is planned with the retrieval finding index publisher"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_dossier_publication", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.WHEN_ENABLED, missing=MissingPolicy.REJECT),
        InputRequirement("job_dossier_publication", "dossier_publications",
                         "appsec-review/dossier-publication/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
        InputRequirement("job_poc_generation", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.WHEN_ENABLED, missing=MissingPolicy.REJECT),
        InputRequirement("job_poc_generation", "poc_generation_summary",
                         "appsec-review/poc-generation-handoff/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_poc_generation", "poc_writer_cells",
                         "appsec-review/poc-writer-receipt/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_poc_generation", "poc_reproducers",
                         "appsec-review/poc-provenance/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_planning", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.WHEN_ENABLED, missing=MissingPolicy.REJECT),
        InputRequirement("job_remediation_planning", "remediation_planning_summary",
                         "appsec-review/remediation-planning/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_planning", "remediation_proposals",
                         "appsec-review/remediation-plan/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_validation", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.WHEN_ENABLED, missing=MissingPolicy.REJECT),
        InputRequirement("job_remediation_validation", "remediation_validation_summary",
                         "appsec-review/remediation-validations/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_validation", "remediation_validation_receipts",
                         "appsec-review/remediation-validation/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    ),
    schedule_after=('job_inference_security_review', 'job_poc_generation', 'job_remediation_planning', 'job_remediation_validation', 'job_dossier_publication'),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
