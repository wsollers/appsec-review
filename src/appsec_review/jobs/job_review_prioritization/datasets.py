"""Dataset publication declarations for job_review_prioritization.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_review_prioritization/attempts/*"
CONSUMES = ('job_review_intake', 'job_target_catalog', 'job_tree_sitter_ast', 'job_source_history_analysis', 'job_evidence_collection', 'job_codeql_analysis')
DATASETS = (
    indexed("priority_items", "publish", "priority", "appsec-review/retrieval-index/2",
            "Ranked review-priority items, review signals, ordered flow steps and dependency context.",
            indexes=("priority",), route="query_hotspots; find/trace index=priority", required=True),
    artifact_only("prioritization_documents", "publish", "priority", "appsec-review/review-prioritization/1",
                  "Syntax facts, dependency graph, semantic evidence and the full ranking.",
                  artifacts=(_A + "/steps/*/tasks/*/artifacts/*.json",),
                  reason="full unselected ranking and per-file syntax facts exceed retrieval bounds; selected "
                         "items are indexed"),
)
