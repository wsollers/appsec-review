"""Validation records are immutable receipts, not changes to finding state."""
from appsec_review.runtime.datasets import artifact_only, protected

CONSUMES = ("job_inference_security_review", "job_remediation_planning", "job_language_build")
_A = "data/jobs/job_remediation_validation/attempts/*/steps"
DATASETS = (
    artifact_only("remediation_validation_summary", "acceptance", "inference_review",
                  "appsec-review/remediation-validations/1", "Assurance-labelled checks and exact candidate accounting.",
                  artifacts=(_A + "/load/**", _A + "/acceptance/**"),
                  reason="downstream consumers use the accepted hash-bound summary"),
    protected("remediation_validation_receipts", "assess", "inference_review",
              "appsec-review/remediation-validation/1",
              "Exact-patch checks, independent semantic assessments, compiler diagnostics and cleanup receipts.",
              artifacts=(_A + "/assess/**",),
              reason="source-derived diagnostics and private semantic assessments stay protected"),
)
