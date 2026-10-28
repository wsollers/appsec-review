"""Dataset publication declarations for ``job_final_publication_gate``."""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_final_publication_gate/attempts/*"
# The gate reads only the accepted inference review handoff and the artifacts it binds.
CONSUMES = ("job_inference_security_review", "job_poc_generation", "job_remediation_planning",
            "job_remediation_validation", "job_dossier_publication")
DATASETS = (
    artifact_only(
        "publication_gate_decisions", "acceptance", "inference_review",
        "appsec-review/final-publication-gate/2",
        "Hash-bound gate document: every finding package classified as publishable, verification backlog "
        "or withheld with exact accounting, the limitations list and the bindings re-verified from bytes.",
        artifacts=(_A + "/steps/load/**", _A + "/steps/gate/**", _A + "/steps/acceptance/**"),
        reason="the gate projects accepted review state and is read by the final report job; a scoped "
               "finding query is planned with the retrieval finding index publisher"),
)
