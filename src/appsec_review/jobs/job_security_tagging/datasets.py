"""Dataset publication declarations for job_security_tagging.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_security_tagging/attempts/*"
CONSUMES = ()
DATASETS = (
    indexed("tag_assignments", "publication", "tags", "appsec-review/tag-assignment/1",
            "Security tag assignments per family with subject and evidence identities.",
            indexes=("tags",), route="find/search/trace index=tags kind=tag_assignment"),
    artifact_only("tagging_documents", "publication", "tags", "appsec-review/security-tagging-handoff/1",
                  "Taxonomy identity, scope, assignment sets, tag cloud and handoff.",
                  artifacts=(_A + "/artifacts/security-tagging/*.json",),
                  reason="same assignments as the tag shards; the tag cloud is a derived roll-up"),
)
