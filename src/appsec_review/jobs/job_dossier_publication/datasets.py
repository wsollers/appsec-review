"""Protected developer artifacts, never a retrieval corpus or public payload."""
from appsec_review.jobs.completion_contracts import DOSSIER_PUBLICATION_SCHEMA
from appsec_review.runtime.datasets import protected

_A = "data/jobs/job_dossier_publication/attempts/*/steps"
DATASETS = (
    protected("dossier_publications", "acceptance", "inference_review", DOSSIER_PUBLICATION_SCHEMA,
                  "Hash-bound protected dossiers, deterministic JSON/LaTeX, real PDFs and rendering receipts.",
                  artifacts=(_A + "/load/**", _A + "/dossiers/**", _A + "/acceptance/**"),
                  reason="protected developer evidence; public reports project only sanitized status and references"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

from appsec_review.jobs.bound_artifacts import source_context_inputs
from appsec_review.jobs.decision_audit_inputs import original_audit_source_inputs

CONTRACT = JobContract(
    inputs=original_audit_source_inputs((
        *source_context_inputs(),
        InputRequirement("job_inference_security_review", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_inference_security_review", "accepted_scope",
                         "appsec-review/inference-review-accepted-scope/1", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_inference_security_review", "lead_triage",
                         "application/json", authority=EvidenceAuthority.PROVISIONAL),
        InputRequirement("job_inference_security_review", "review_packages",
                         "appsec-review/review-package/7", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_inference_security_review", "review_cells",
                         "appsec-review/cell-attempt-receipt/1", authority=EvidenceAuthority.PROVISIONAL),
        InputRequirement("job_inference_security_review", "claim_ledger",
                         "appsec-review/ledger-event/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_inference_security_review", "attack_chains",
                         "appsec-review/attack-chain-manifest/1", authority=EvidenceAuthority.PROVISIONAL),
        InputRequirement("job_inference_security_review", "scores_and_findings",
                         "appsec-review/finding-package/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_inference_security_review", "review_audit_metadata",
                         "appsec-review/review-audit-publication/1", authority=EvidenceAuthority.OPERATIONAL,
                         availability=Availability.WHEN_DECLARED, missing=MissingPolicy.GAP),
        *(InputRequirement("job_inference_security_review", kind, schema,
                           authority=EvidenceAuthority.OPERATIONAL, availability=Availability.WHEN_DECLARED,
                           missing=MissingPolicy.NOT_APPLICABLE)
          for kind, schema in (
              ("review_decision_audit", "appsec-review/review-audit-manifest/1"),
              ("review_decisions", "appsec-review/review-decision/1"),
              ("review_verification_coverage", "appsec-review/verification-coverage/1"),
              ("review_decision_bases", "appsec-review/decision-basis/1"),
              ("review_audit_continuations", "application/x-ndjson"),
          )),
        InputRequirement("job_poc_generation", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_poc_generation", "poc_generation_summary",
                         "appsec-review/poc-generation-handoff/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_poc_generation", "poc_writer_cells",
                         "appsec-review/poc-writer-receipt/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_poc_generation", "poc_reproducers",
                         "appsec-review/poc-provenance/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_planning", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_planning", "remediation_planning_summary",
                         "appsec-review/remediation-planning/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_planning", "remediation_proposals",
                         "appsec-review/remediation-plan/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_validation", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_validation", "remediation_validation_summary",
                         "appsec-review/remediation-validations/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_remediation_validation", "remediation_validation_receipts",
                         "appsec-review/remediation-validation/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    )),
    schedule_after=('job_inference_security_review', 'job_poc_generation', 'job_remediation_planning', 'job_remediation_validation'),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
