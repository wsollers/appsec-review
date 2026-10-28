"""Dataset publication declarations for job_change_context_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_change_context_analysis/attempts/*"
CONSUMES = ('job_target_catalog', 'job_source_history_analysis', 'job_tree_sitter_ast')
DATASETS = (
    indexed("change_context", "publish", "change_context", "appsec-review/retrieval-index/2",
            "Ranked change-context signals, changes, review units and deployment events.",
            indexes=("history",), prefixes=("change-context",),
            route="query_change_context; query_precomputed query_set=history_context"),
    artifact_only("change_context_documents", "publish", "change_context",
                  "appsec-review/change-context-analysis/1",
                  "Attribution, change records, unit signals and ranking documents.",
                  artifacts=(_A + "/steps/*/tasks/*/artifacts/*.json",
                             _A + "/steps/*/tasks/*/sources/*/artifacts/*.json",),
                  reason="normalized inputs of the change-context shard; pseudonym maps are never indexed",
                  sensitivity="sensitive"),
    protected("operator_exports", "load", "change_context", "application/json",
              "Verbatim operator review, deployment and organization exports.",
              artifacts=(_A + "/steps/load/tasks/external_sources/artifacts/inputs/*",
                         _A + "/steps/load/tasks/external_sources/sources/*/artifacts/inputs/*",),
              reason="unredacted operator-supplied records; only normalized bounded facts are indexed"),
    protected("change_context_tool_io", "attribute", "change_context", "appsec-review/container-execution/1",
              "Git blame and diff container scratch.",
              artifacts=(_A + "/steps/*/tasks/*/scratch/**",
                         _A + "/steps/*/tasks/*/sources/*/scratch/**",), reason=RAW),
)
