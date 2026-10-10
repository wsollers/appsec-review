"""Dataset publication declarations for job_ci_configuration_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_ci_configuration_analysis/attempts/*"
CONSUMES = ('job_target_catalog',)
DATASETS = (
    indexed("ci_observations", "ci_observation_publication", "ci", "appsec-review/retrieval-index/2",
            "Normalized CI observations with provider, workflow, job and step hierarchy.",
            indexes=("observations",), prefixes=("ci_",),
            route="query_ci_configuration; query_precomputed query_set=ci_trust"),
    indexed("ci_findings", "ci_correlation", "ci", "appsec-review/retrieval-index/2",
            "Canonical CI findings correlated across tools.",
            indexes=("evidence",), prefixes=("ci_findings",), route="query_ci_configuration canonical_finding"),
    artifact_only("ci_documents", "ci_coverage", "ci", "appsec-review/ci-configuration-analysis-handoff/1",
                  "CI definitions, classifications, normalized observations, hierarchy and coverage.",
                  artifacts=(_A + "/artifacts/ci/*/*.json",),
                  reason="same redacted records as the CI observation and finding shards"),
    protected("ci_tool_io", "ci_analysis", "ci", "appsec-review/container-execution/1",
              "Raw CI linter output and streams.",
              artifacts=(_A + "/steps/ci_analysis/tasks/*/scratch/**",), reason=RAW),
)
