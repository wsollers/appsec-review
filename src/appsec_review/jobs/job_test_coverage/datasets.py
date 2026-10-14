"""Dataset declarations for the test-coverage ingestion job."""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_test_coverage/attempts/*"
CONSUMES = ("job_target_catalog", "job_language_build", "job_artifact_indexing")
DATASETS = (
    indexed("test_coverage", "index", "build", "appsec-review/retrieval-index/2",
            "Bound test-coverage counts and rates by accepted source file and build unit.",
            indexes=("analysis",), prefixes=("test-coverage-",),
            route="query_precomputed query_set=test_coverage"),
    artifact_only("test_coverage_handoff", "acceptance", "build",
                  "appsec-review/test-coverage-handoff/1",
                  "Accepted coverage accounting, source bindings, and named gaps.",
                  artifacts=(_A + "/artifacts/test-coverage/*.json",),
                  reason="normalized coverage rows are indexed in immutable analysis shards"),
)
