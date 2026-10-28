"""Publication declarations for dependency intelligence."""

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_dependency_intelligence/attempts/*"
CONSUMES = ("job_target_catalog", "job_language_build", "job_artifact_indexing", "job_evidence_collection")
DATASETS = (
    artifact_only("native_discovery", "resolution", "inventory", "appsec-review/native-discovery/1",
                  "Bounded native package claims, source evidence, and explicit coverage gaps.",
                  artifacts=(_A + "/steps/resolution/tasks/detect_dependencies/native-discovery.json",),
                  reason="native evidence and dependency claims are also indexed"),
    artifact_only("native_spdx", "publication", "inventory", "SPDX-2.3",
                  "Validated SPDX 2.3 source inventory and evidence-backed native enrichment.",
                  artifacts=(_A + "/steps/publication/tasks/publish_sbom/*.spdx.json",),
                  reason="standard SPDX documents are exposed by the accepted dependency handoff"),
    artifact_only("native_sbom_provenance", "publication", "inventory",
                  "appsec-review/native-sbom-provenance/1",
                  "SPDX package derivations, merge decisions, and coverage.",
                  artifacts=(_A + "/steps/publication/tasks/publish_sbom/native-sbom-provenance.json",),
                  reason="whole-document provenance; resolving native evidence is indexed"),
    artifact_only("native_sbom_metrics", "publication", "inventory", "appsec-review/native-sbom-metrics/1",
                  "Hash-bound discovery, conversion, validation, and publication counters.",
                  artifacts=(_A + "/steps/publication/tasks/publish_sbom/native-sbom-metrics.json",),
                  reason="semantic counters are aggregated by run telemetry"),
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
