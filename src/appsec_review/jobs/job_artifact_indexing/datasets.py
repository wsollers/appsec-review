"""Dataset publication declarations for job_artifact_indexing.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_artifact_indexing/attempts/*"
DATASETS = (
    indexed("artifact_catalog", "index", "artifacts", "appsec-review/retrieval-index/2",
            "Produced artifacts and target-intake artifacts with exact hashes and distinct provenance.",
            indexes=("artifacts",), prefixes=("catalog-",),
            route="query_artifacts; query_precomputed query_set=artifact_inventory"),
    indexed("archive_members", "index", "artifacts", "appsec-review/retrieval-index/2",
            "Members of produced package archives.",
            indexes=("artifacts",), prefixes=("members-",), route="query_artifacts kind=archive_member"),
    indexed("artifact_relationships", "index", "artifacts", "appsec-review/retrieval-index/2",
            "Producing-action and link relationships for produced artifacts.",
            indexes=("artifacts",), prefixes=("relations-",),
            route="trace relations=GENERATED_FROM,LINKS_INTO; query_artifacts producing_build_action"),
    artifact_only("artifact_index_summary", "acceptance", "artifacts", "appsec-review/artifact-indexing/1",
                  "Accepted artifact-index summary and shard locks.",
                  artifacts=(_A + "/artifacts/artifact-indexing/*.json", "data/indices/artifacts/*.lock"),
                  reason="counts and shard identities already published by the artifacts index"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
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
                         "appsec-review/language-build-handoff/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
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
    schedule_after=('job_language_build',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
