"""Protected attempt-owned proposals and source context, never a target mutation."""
from appsec_review.runtime.datasets import artifact_only, protected

CONSUMES = ("job_inference_security_review", "job_language_build")
_A = "data/jobs/job_remediation_planning/attempts/*/steps"
DATASETS = (
    artifact_only("remediation_planning_summary", "acceptance", "inference_review",
                  "appsec-review/remediation-planning/1", "Exact confirmed-only planning outcomes and gaps.",
                  artifacts=(_A + "/load/**", _A + "/acceptance/**"),
                  reason="downstream consumers use the accepted hash-bound summary"),
    protected("remediation_proposals", "assess", "inference_review", "appsec-review/remediation-plan/1",
              "Inert patches, regression specifications, resolving source context and model receipts.",
              artifacts=(_A + "/assess/**",),
              reason="source excerpts and untrusted model proposals are protected developer artifacts"),
)
