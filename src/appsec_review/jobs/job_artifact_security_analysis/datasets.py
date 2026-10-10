"""Dataset publication declarations for job_artifact_security_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_artifact_security_analysis/attempts/*"
CONSUMES = ('job_language_build', 'job_artifact_indexing')
DATASETS = (
    indexed("artifact_security_observations", "index", "scanner_findings", "appsec-review/retrieval-index/2",
            "Per-artifact format, hardening, SBOM and vulnerability scanner observations.",
            indexes=("observations",), prefixes=("artifact-security",),
            route="query_artifacts scanner/tool; query_precomputed query_set=dependency_advisories"),
    artifact_only("artifact_security_results", "analyze", "sbom", "appsec-review/artifact-security-observation/1",
                  "Untruncated per-artifact scanner results, including SBOM and vulnerability matches.",
                  artifacts=("data/artifact-security/shards/**", _A + "/artifacts/artifact-security/*.json"),
                  reason="complete scanner documents exceed payload bounds; bounded observations are indexed and "
                         "package/advisory pairs are published as precomputed facts"),
    protected("artifact_scanner_io", "analyze", "scanner_findings", "appsec-review/container-execution/1",
              "Scanner streams, container scratch and copied feed databases.",
              artifacts=(_A + "/artifacts/asa/**", _A + "/steps/analyze/tasks/*/containers/**"), reason=RAW),
)
