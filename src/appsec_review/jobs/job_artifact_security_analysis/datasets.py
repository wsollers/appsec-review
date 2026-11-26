"""Dataset publication declarations for job_artifact_security_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_artifact_security_analysis/attempts/*"
DATASETS = (
    indexed("artifact_security_observations", "index", "scanner_findings", "appsec-review/retrieval-index/2",
            "Per-artifact format, hardening, SBOM and vulnerability scanner observations.",
            indexes=("observations",), prefixes=("artifact-security",),
            route="query_artifacts scanner/tool; query_precomputed query_set=dependency_advisories"),
    artifact_only("artifact_security_results", "analyze", "sbom", "appsec-review/artifact-security-observation/1",
                  "Per-artifact scanner results with explicit parser bounds and immutable native output references.",
                  artifacts=("data/artifact-security/shards/*/*/result.json",),
                  reason="complete scanner documents exceed payload bounds; bounded observations are indexed and "
                         "package/advisory pairs are published as precomputed facts"),
    artifact_only("artifact_security_acceptance", "acceptance", "sbom", "appsec-review/artifact-security-analysis/1",
                  "Accepted artifact-security summary, disposition, and shard inventory.",
                  artifacts=(_A + "/artifacts/artifact-security/accepted-analysis.json",),
                  reason="acceptance summary governs job disposition and shard inventory; findings are queried "
                         "through the artifact-security index"),
    protected("artifact_scanner_io", "analyze", "scanner_findings", "appsec-review/container-execution/1",
              "Scanner streams, container scratch, copied feed databases and read-only input mount placeholders.",
              artifacts=(_A + "/artifacts/asa/**", _A + "/steps/analyze/tasks/*/containers/**",
                         _A + "/steps/analyze/tasks/*/target-inputs/**",
                         _A + "/steps/analyze/tasks/*/installer-records/**"), reason=RAW),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_artifact_indexing", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_artifact_indexing", "artifact_catalog",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "archive_members",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "artifact_relationships",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "artifact_index_summary",
                         "appsec-review/artifact-indexing/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
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
                         "appsec-review/language-build-handoff/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_language_build", "build_workspaces",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_third_party_data_sync", "feed_snapshot",
                         "appsec-review/public-feed-use/1", channel=InputChannel.EXTERNAL,
                         authority=EvidenceAuthority.REFERENCE),
    ),
    schedule_after=('job_artifact_indexing',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
