"""Publication declarations for ``job_poc_generation``.

The reproducer files are developer-facing data: they are stored verbatim, hash-bound by the handoff,
and never indexed as text or executed. The writer's briefs and receipts carry
target source excerpts and untrusted model output, so they are protected.
"""
from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, protected


_A = "data/jobs/job_poc_generation/attempts/*/steps"
# The job reads the accepted review directly and the accepted native build; it writes
# attempt-owned files consumed by the optional engineering jobs and the publication gate.
DATASETS = (
    artifact_only(
        "poc_generation_summary", "publish", "inference_review", "appsec-review/poc-generation-handoff/2",
        "Hash-bound list of every proof-of-concept candidate with its status, bounded description, file "
        "references and named gaps, plus the verified inputs, the validator outcome and the compile record.",
        artifacts=(_A + "/load/**", _A + "/validate/**", _A + "/compile/**", _A + "/package/tasks/files/package.json",
                   _A + "/publish/**"),
        reason="the gate verifies the accepted summary and freezes public references; a scoped finding query is "
               "planned with the retrieval finding index publisher"),
    protected(
        "poc_writer_cells", "write", "inference_review", "appsec-review/poc-writer-receipt/1",
        "The writer's briefs (target source excerpts and package views) and per-candidate receipts with hashes, "
        "counts and the validated answer; raw prompts are never stored.",
        artifacts=(_A + "/plan/**", _A + "/write/**"),
        reason="briefs carry target source text and the answers are untrusted model output kept for audit only"),
    protected(
        "poc_reproducers", "package", "inference_review", "appsec-review/poc-provenance/2",
        "Per candidate: the proof-of-concept source (two functions, no main), compile.json, README.md and "
        "provenance.json under the immutable package.files attempt directory.",
        artifacts=(_A + "/package/tasks/files/candidates/**",),
        reason="model-written source is stored verbatim as data for developers and is never indexed as text, "
               "linked or executed; the report and the handoff carry its hashes"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

from appsec_review.jobs.bound_artifacts import source_context_inputs

CONTRACT = JobContract(
    inputs=(
        *source_context_inputs(),
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
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
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
    schedule_after=('job_inference_security_review',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
