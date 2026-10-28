"""Protected developer artifacts, never a retrieval corpus or public payload."""
from appsec_review.jobs.completion_contracts import DOSSIER_PUBLICATION_SCHEMA
from appsec_review.runtime.datasets import protected

CONSUMES = ("job_inference_security_review", "job_poc_generation",
            "job_remediation_planning", "job_remediation_validation")
_A = "data/jobs/job_dossier_publication/attempts/*/steps"
DATASETS = (
    protected("dossier_publications", "acceptance", "inference_review", DOSSIER_PUBLICATION_SCHEMA,
                  "Hash-bound protected dossiers, deterministic JSON/LaTeX, real PDFs and rendering receipts.",
                  artifacts=(_A + "/load/**", _A + "/dossiers/**", _A + "/acceptance/**"),
                  reason="protected developer evidence; public reports project only sanitized status and references"),
)
