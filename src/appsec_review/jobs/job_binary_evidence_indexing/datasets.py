"""Dataset publication declarations for job_binary_evidence_indexing.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_binary_evidence_indexing/attempts/*"
CONSUMES = ("job_review_intake",)
DATASETS = (
    indexed("binary_functions", "index", "binary", "appsec-review/retrieval-index/2",
            "Ghidra functions, call sites, imports and strings of each frozen binary publication, with "
            "CALLS and REFERENCES relations; decompiled functions are located in run-owned pseudo-C.",
            indexes=("binary",), prefixes=("binary-",),
            route="find/trace index=binary kind=binary_function|binary_call_site|binary_import|binary_string; "
                  "read_excerpt for pseudo-C lines"),
    artifact_only("binary_pseudo_c", "index", "binary", "appsec-review/binary-source-backing/1",
                  "Detached pseudo-C bytes and their binary, address and publication binding.",
                  artifacts=("data/binary-evidence/sources/*.json",),
                  reason="served only through read_excerpt on an accepted binary entity location"),
    artifact_only("binary_evidence_summary", "acceptance", "binary", "appsec-review/binary-evidence-index/1",
                  "Binary-evidence index summary with per-binary counts and gaps.",
                  artifacts=(_A + "/steps/acceptance/tasks/publish_handoff/*.json",),
                  reason="counts and binary identities already published as coverage"),
)
