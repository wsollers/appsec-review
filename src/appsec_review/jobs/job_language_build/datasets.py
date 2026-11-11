"""Dataset publication declarations for job_language_build.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_language_build/attempts/*"
DATASETS = (
    protected("topology_refinement_inputs", "execute", "build",
              "appsec-review/build-topology-refinement/1",
              "Immutable replacement and promotion refinements, including their complete accepted inputs.",
              artifacts=("artifacts/build/topology/**", "data/build/topology/**"),
              reason="closures retain source documents and exact effective environment values; "
                     "only sanitized identities and coverage are retrieval metadata"),
    indexed("build_actions", "acceptance", "build", "appsec-review/retrieval-index/2",
            "Sanitized build commands, produced artifacts and package relationships per build unit.",
            indexes=("build",), prefixes=("language-build",),
            route="find/trace index=build; query_precomputed query_set=build_provenance"),
    indexed("jvm_build_actions", "execute", "build", "appsec-review/retrieval-index/2",
            "Sanitized JVM build commands, observed tool invocations and artifacts.",
            indexes=("build",), prefixes=("jvm-",), route="find/trace index=build"),
    artifact_only("language_build_receipts", "acceptance", "build", "appsec-review/language-build-handoff/2",
                  "Accepted build receipts with topology, dependency identities and artifact hashes.",
                  artifacts=(_A + "/artifacts/language-build/*.json",),
                  reason="receipts embed exact recipes and environment values; sanitized facts are in the build "
                         "index", sensitivity="sensitive"),
    protected("build_workspaces", "execute", "build", "application/octet-stream",
              "Build workspaces, execution capture, protected argv and environment, link databases and logs.",
              artifacts=("data/build/native/**", "data/build/go/**", "data/build/dotnet/**", "data/build/node/**",
                         "data/build/python/**", "data/build/rust/**", "data/build/php/**", "data/build/jvm/**",
                         "data/build/java/**", "data/build/wasm/**"),
              reason="exact argv, environment values, raw logs, file-access captures and built binaries"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        # load_accepted_plan (dispatch guards, refinement and .NET topology) re-reads the environment
        # publication the accepted plan is bound to, so that producer is a declared, optional input.
        # job_build_iteration inherits these inputs.
        InputRequirement("job_build_environment_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.OPERATIONAL),
        InputRequirement("job_build_environment_analysis", "build_environment",
                         "appsec-review/build-environment-analysis/1", authority=EvidenceAuthority.OPERATIONAL),
        InputRequirement("job_project_build", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_project_build", "topology_refinement_inputs",
                         "appsec-review/build-topology-refinement/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_project_build", "project_build_dispatch",
                         "appsec-review/project-build-dispatch/3", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_project_build", "probe_workspaces",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_project_build", "image_build_streams",
                         "text/plain", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
    ),
    schedule_after=('job_project_build',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
