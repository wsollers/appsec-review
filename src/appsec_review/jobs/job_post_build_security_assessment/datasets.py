"""Dataset publication declarations for job_post_build_security_assessment.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_post_build_security_assessment/attempts/*"
CONSUMES = ('job_cpp_compiled_analysis',)
DATASETS = (
    indexed("build_security", "index", "build", "appsec-review/retrieval-index/2",
            "Redacted native build actions, binary inspections, deterministic checks and validated observations.",
            indexes=("build_security",), route="query_build_security"),
    artifact_only("build_security_documents", "publication", "build",
                  "appsec-review/post-build-security-assessment/1",
                  "Command provenance, binary inspections, deterministic and inference results per case.",
                  artifacts=(_A + "/steps/*/tasks/*/*/*.json", _A + "/steps/publication/tasks/publish_handoff/*.json"),
                  reason="full symbol and section tables exceed payload bounds; bounded records are indexed"),
)
