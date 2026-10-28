"""Dataset publication declarations for job_owasp_control_assessment.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_owasp_control_assessment/attempts/*"
from appsec_review.owasp_workbench.evidence import UPSTREAM_JOBS

CONSUMES = UPSTREAM_JOBS
DATASETS = (
    indexed("owasp_workbench", "publication", "owasp", "appsec-review/owasp-index-shard/1",
            "Standards, component classifications, applicability, validation work, finding packages and "
            "control results.",
            indexes=("standards", "component-classification", "applicability", "validation-work",
                     "control-result", "finding-package"),
            artifacts=("data/indexes/owasp/**",),
            route="query_owasp_workbench; query_precomputed query_set=control_evidence", store="owasp"),
    artifact_only("owasp_documents", "publication", "owasp", "appsec-review/owasp-workbench-result/1",
                  "Workbench source documents and the accepted result.",
                  artifacts=(_A + "/artifacts/owasp-workbench/*.json",),
                  reason="same records as the accepted workbench shards"),
)
