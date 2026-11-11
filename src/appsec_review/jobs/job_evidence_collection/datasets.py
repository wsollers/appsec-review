"""Dataset publication declarations for job_evidence_collection.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_evidence_collection/attempts/*"
DATASETS = (
    indexed("static_tool_observations", "evidence_publication", "scanner_findings",
            "appsec-review/retrieval-index/2",
            "Normalized static-tool observations, one shard per tool, including software inventory and "
            "vulnerability matches.",
            indexes=("observations",),
            route="find/search index=observations; query_precomputed query_set=scanner_correlation"),
    artifact_only("static_tool_evidence", "evidence_publication", "scanner_findings",
                  "appsec-review/static-tool-evidence/2",
                  "Normalized per-tool evidence documents, checkpoints and the evidence handoff.",
                  artifacts=(_A + "/steps/*/tasks/*/evidence.json", _A + "/steps/*/tasks/*/handoff.json",
                             "data/task-checkpoints/job_evidence_collection/**"),
                  reason="same normalized records as the per-tool observation shards"),
    protected("static_tool_io", "source_sast", "scanner_findings", "appsec-review/container-execution/1",
              "Raw scanner output, staged inputs, SBOMs and execution streams.",
              artifacts=(_A + "/steps/*/tasks/*/scratch/**", _A + "/steps/*/tasks/*/inputs/**",
                         _A + "/steps/vulnerability_matching/tasks/osv_scanner_scan/osv-scanner-merged.json"),
              reason="raw scanner output can contain secret matches and unbounded target content"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_build_environment_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.OPERATIONAL),
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
        InputRequirement("job_target_analysis_plan", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_analysis_plan", "planning_feedback_cache",
                         "appsec-review/target-analysis-proposal/3", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_analysis_plan", "analysis_plan",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_analysis_plan", "analysis_plan_documents",
                         "appsec-review/target-analysis-plan/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
        InputRequirement("job_third_party_data_sync", "feed_snapshot",
                         "appsec-review/public-feed-use/1", channel=InputChannel.EXTERNAL,
                         authority=EvidenceAuthority.REFERENCE),
    ),
    schedule_after=('job_target_analysis_plan',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
