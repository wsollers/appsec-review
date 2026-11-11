"""Dataset declarations for bounded execution-profile ingestion."""

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_profile_data/attempts/*"
DATASETS = (
    indexed("profile_data", "index", "build", "appsec-review/retrieval-index/2",
            "Accepted execution-profile samples and context-only within-build hotness ranks.",
            indexes=("analysis",), prefixes=("profile-data-",),
            route="query_precomputed query_set=profile_data"),
    artifact_only("profile_data_handoff", "acceptance", "build",
                  "appsec-review/profile-data-handoff/1",
                  "Accepted profile reports, normalized row accounting, and explicit gaps.",
                  artifacts=(_A + "/artifacts/profile-data/*.json",),
                  reason="normalized profile rows are indexed in immutable analysis shards"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_artifact_indexing", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "artifact_catalog",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "archive_members",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "artifact_relationships",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "artifact_index_summary",
                         "appsec-review/artifact-indexing/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
    schedule_after=('job_artifact_indexing',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
