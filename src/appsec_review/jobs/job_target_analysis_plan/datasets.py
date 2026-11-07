"""Dataset publication declarations for job_target_analysis_plan.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_target_analysis_plan/attempts/*"
DATASETS = (
    protected("planning_feedback_cache", "analysis_decisions", "analysis_plan",
              "appsec-review/target-analysis-proposal/3",
              "Validated complete bounded feedback and exact additive evidence.",
              artifacts=("data/planning-feedback/*.json",),
              reason="immutable source/environment/profile/prompt/model keyed cache; not a retrieval endpoint"),
    indexed("analysis_plan", "plan_acceptance", "analysis_plan", "appsec-review/retrieval-index/2",
            "Accepted components, scanner selections and planned build actions.",
            indexes=("analysis",), prefixes=("target-analysis-plan",),
            route="find/search/trace index=analysis shard=target-analysis-plan", required=True),
    artifact_only("analysis_plan_documents", "plan_acceptance", "analysis_plan",
                  "appsec-review/target-analysis-plan/1", "Catalog summary and accepted analysis plan documents.",
                  artifacts=(_A + "/artifacts/analysis-plan/*.json",),
                  reason="source documents of the analysis-plan shard; accepted recipes carry exact commands",
                  sensitivity="sensitive"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_build_environment_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.OPERATIONAL,
                         availability=Availability.WHEN_ENABLED, missing=MissingPolicy.GAP),
        InputRequirement("job_build_environment_analysis", "build_environment",
                         "appsec-review/build-environment-analysis/1", authority=EvidenceAuthority.OPERATIONAL),
        InputRequirement("job_review_intake", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "model_preflight",
                         "appsec-review/model-preflight/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "binary_evidence",
                         "appsec-review/binary-evidence-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "review_intake",
                         "appsec-review/review-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_source_history_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_source_history_analysis", "history_signals",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_source_history_analysis", "history_documents",
                         "appsec-review/source-history-analysis/2", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_source_history_analysis", "raw_git_history",
                         "application/octet-stream", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_source_history_analysis", "history_tool_io",
                         "appsec-review/container-execution/1", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_target_catalog", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_target_catalog", "target_artifact_inputs",
                         "appsec-review/target-artifact-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "source_files",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "declaration_symbols",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "components",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "target_documents",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "build_units",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "catalog_documents",
                         "appsec-review/target-catalog/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    ),
    schedule_after=('job_ci_configuration_analysis', 'job_source_history_analysis', 'job_build_environment_analysis'),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
