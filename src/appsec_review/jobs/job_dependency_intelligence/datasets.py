"""Publication declarations for dependency intelligence."""

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_dependency_intelligence/attempts/*"
CONSUMES = ("job_target_catalog", "job_language_build", "job_artifact_indexing", "job_evidence_collection")
DATASETS = (
    indexed("dependency_context", "publication", "inventory", "appsec-review/retrieval-index/2",
            "Deduplicated dependency identities, native provenance, Scorecard context, and scoped gaps.",
            indexes=("inventory",), prefixes=("dependency-intelligence",),
            route="find/search index=inventory kind=dependency_package,review_signal; query_precomputed query_set=dependency_advisories"),
    artifact_only("scorecard_responses", "scorecards", "inventory", "application/json",
                  "Exact bounded OpenSSF Scorecard responses retained with hashes.",
                  artifacts=(_A + "/steps/scorecards/tasks/fetch/artifacts/scorecards/*.json",),
                  reason="raw responses are retained for reproducibility; normalized context is indexed"),
    artifact_only("dependency_intelligence_handoff", "acceptance", "inventory",
                  "appsec-review/dependency-intelligence-handoff/1",
                  "Accepted dependency, repository, Scorecard, gap, and retrieval-manifest identities.",
                  artifacts=(_A + "/steps/acceptance/tasks/publish_handoff/*.json",),
                  reason="the retrieval shard is the queryable representation"),
)
