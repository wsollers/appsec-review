"""Protected local exports; retrieval exposes sanitized inventory metadata only."""
from appsec_review.runtime.datasets import protected

from .contracts import OPENVEX_EXPORT_RESULT_SCHEMA, VERIFIED_INPUTS_SCHEMA

_A = "data/jobs/job_openvex_export/attempts/*/steps"
_E = _A + "/export/tasks/assemble/"
_REASON = "Internal vulnerability disclosure artifacts; no content retrieval or external publication."
DATASETS = (
    protected("openvex_dependency_documents", "export", "inference_review", "https://openvex.dev/ns/v0.2.0",
              "Optional admitted dependency reachability statements; no inferred negative VEX claims.",
              artifacts=(_E + "openvex-dependencies.json",), reason=_REASON),
    protected("openvex_dependency_accounting", "export", "inference_review",
              "appsec-review/openvex-dependencies/1",
              "Dependency export source pins, statement counts and coverage gaps.",
              artifacts=(_E + "openvex-dependencies-result.json",), reason=_REASON),
    protected("openvex_verified_inputs", "load", "inference_review", VERIFIED_INPUTS_SCHEMA,
              "Verified accepted review boundary and exact offline schema snapshots.",
              artifacts=(_A + "/load/**",), reason=_REASON),
    protected("openvex_documents", "export", "inference_review", "https://openvex.dev/ns/v0.2.0",
              "Affected-only statements for the exact reviewed source snapshot and configuration.",
              artifacts=(_E + "openvex.json",), reason=_REASON),
    protected("openvex_export_accounting", "acceptance", "inference_review", OPENVEX_EXPORT_RESULT_SCHEMA,
              "Exact included/excluded accounting, companion manifest and accepted result.",
              artifacts=(_E + "openvex-manifest.json", _E + "openvex-result.json", _A + "/acceptance/**"),
              reason=_REASON),
)


from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_review_intake", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.OPTIONAL, missing=MissingPolicy.NOT_APPLICABLE),
        InputRequirement("job_dependency_intelligence", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.OPTIONAL, missing=MissingPolicy.NOT_APPLICABLE),
        InputRequirement("job_dependency_intelligence", "sca_reachability", "appsec-review/sca-reachability/1",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.OPTIONAL, missing=MissingPolicy.NOT_APPLICABLE),
        InputRequirement("job_final_publication_gate", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_final_publication_gate", "publication_gate_decisions",
                         "appsec-review/final-publication-gate/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
        # The export recomputes the gate's classification from the same audited document the gate classified, so
        # it reads the decision audit exactly as job_final_publication_gate declares it. Run 2026-11-16-0004 failed
        # its last job on "undeclared consumption ... review_audit_metadata" without these rows.
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
    ),
    schedule_after=('job_final_publication_gate',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
