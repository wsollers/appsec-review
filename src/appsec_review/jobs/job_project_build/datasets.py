"""Dataset publication declarations for job_project_build.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_project_build/attempts/*"
DATASETS = (
    protected("topology_refinement_inputs", "plan", "build",
              "appsec-review/build-topology-refinement/1",
              "Immutable complete source inputs, accepted recipe refinements and their acceptance references.",
              artifacts=("artifacts/build/topology/**", "data/build/topology/**"),
              reason="closures retain source documents and exact effective environment values; "
                     "only sanitized identities and coverage are retrieval metadata"),
    artifact_only("project_build_dispatch", "acceptance", "build", "appsec-review/project-build-dispatch/2",
                  "Accepted image, probe and build dispatch decisions per build unit.",
                  artifacts=(_A + "/artifacts/project-build/*.json",),
                  reason="carries exact recipes and environment values; language-build publishes the sanitized "
                         "build index", sensitivity="sensitive"),
    protected("probe_workspaces", "probe", "build", "application/octet-stream",
              "Probe workspaces, kernel execution capture, protected commands and build logs.",
              artifacts=("data/build/probes/**",),
              reason="exact argv, environment values, raw logs and file-access captures"),
    protected("image_build_streams", "image", "build", "text/plain",
              "Image build and repair streams, repair Dockerfiles and raw repair model responses.",
              artifacts=(_A + "/steps/image/tasks/*/*/**", _A + "/steps/probe/tasks/*/*/**"),
              reason="raw build output and raw model responses must not enter retrieval"),
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
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
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
    schedule_after=('job_target_analysis_plan',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
