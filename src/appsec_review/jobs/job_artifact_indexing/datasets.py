"""Dataset publication declarations for job_artifact_indexing.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_artifact_indexing/attempts/*"
CONSUMES = ('job_language_build', 'job_target_catalog')
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
