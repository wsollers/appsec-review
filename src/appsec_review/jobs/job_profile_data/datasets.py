"""Dataset declarations for bounded execution-profile ingestion."""

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_profile_data/attempts/*"
CONSUMES = ("job_target_catalog", "job_language_build", "job_artifact_indexing")
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
