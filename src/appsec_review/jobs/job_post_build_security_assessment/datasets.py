"""Dataset publication declarations for job_post_build_security_assessment.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_post_build_security_assessment/attempts/*"
DATASETS = (
    indexed("build_security", "index", "build", "appsec-review/retrieval-index/2",
            "Redacted native build actions, binary inspections, deterministic checks and validated observations.",
            indexes=("build_security",), route="query_build_security"),
    artifact_only("build_security_documents", "publication", "build",
                  "appsec-review/post-build-security-assessment/1",
                  "Command provenance, binary inspections, deterministic and inference results per case.",
                  artifacts=(_A + "/steps/*/tasks/*/*/*.json", _A + "/steps/publication/tasks/publish_handoff/*.json"),
                  reason="full symbol and section tables exceed payload bounds; bounded records are indexed"),
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
        InputRequirement("job_cpp_compiled_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_build_graph",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "clang_ast",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "llvm_ir",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "infer_observations",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "binary_symbols",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_blocked_branches",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_plan_and_summary",
                         "appsec-review/cpp-compiled-analysis/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_case_material",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "topology_refinement_inputs",
                         "appsec-review/build-topology-refinement/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "build_actions",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "jvm_build_actions",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "language_build_receipts",
                         "appsec-review/language-build-handoff/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "build_workspaces",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_project_build", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_project_build", "topology_refinement_inputs",
                         "appsec-review/build-topology-refinement/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_project_build", "project_build_dispatch",
                         "appsec-review/project-build-dispatch/3", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_project_build", "probe_workspaces",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_project_build", "image_build_streams",
                         "text/plain", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
    ),
    schedule_after=('job_cpp_compiled_analysis',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
