"""Dataset publication declarations for job_target_catalog.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_target_catalog/attempts/*"
CONSUMES = ('job_review_intake',)
DATASETS = (
    indexed("source_files", "retrieval_indexes", "source", "appsec-review/retrieval-index/2",
            "Accepted source files with language, size, hash and bounded text.",
            indexes=("source",), route="find/search/read_excerpt index=source", required=True),
    indexed("declaration_symbols", "retrieval_indexes", "symbols", "appsec-review/retrieval-index/2",
            "Bounded declaration-pattern symbols with line-exact locations.",
            indexes=("analysis",), route="find/search/trace index=analysis kind=symbol", required=True),
    indexed("components", "retrieval_indexes", "catalog", "appsec-review/retrieval-index/2",
            "Catalogued components and their manifests.",
            indexes=("components",), route="find/search index=components", required=True),
    indexed("build_units", "publish_catalog", "build", "appsec-review/retrieval-index/2",
            "Discovered build units and compile-database identities.",
            indexes=("build",), route="find/search index=build kind=build_action", required=True),
    artifact_only("catalog_documents", "publish_catalog", "catalog", "appsec-review/target-catalog/1",
                  "Repository partition, language census, projects, build systems, components and dependencies.",
                  artifacts=(_A + "/artifacts/catalog/*.json",),
                  reason="normalized inputs of the source, analysis, components and build shards; the shards are "
                         "the queryable representation"),
)
