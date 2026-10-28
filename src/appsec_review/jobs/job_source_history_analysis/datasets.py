"""Dataset publication declarations for job_source_history_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_source_history_analysis/attempts/*"
CONSUMES = ('job_review_intake', 'job_target_catalog')
DATASETS = (
    indexed("history_signals", "publish", "history", "appsec-review/retrieval-index/2",
            "Change, file, symbol and component history signals and SII hotspots with pseudonymous authors.",
            indexes=("history",), prefixes=("git-history",),
            route="find/search/trace index=history; query_precomputed query_set=history_context"),
    artifact_only("history_documents", "publish", "history", "appsec-review/source-history-analysis/2",
                  "Normalized changes, classification, signals, line history, symbol spans and hotspots.",
                  artifacts=(_A + "/steps/*/tasks/*/artifacts/*.json",
                             _A + "/steps/*/tasks/*/sources/*/artifacts/*.json",),
                  reason="normalized inputs of the history shard; full per-change lists exceed retrieval bounds"),
    protected("raw_git_history", "acquire", "history", "application/octet-stream",
              "Raw git log and commit messages, including author e-mail addresses.",
              artifacts=(_A + "/steps/acquire/tasks/git_history/protected/*",
                         _A + "/steps/acquire/tasks/git_history/sources/*/protected/*",),
              reason="raw author identities and commit message text; only pseudonyms and classifications are indexed"),
    protected("history_tool_io", "analyze", "history", "appsec-review/container-execution/1",
              "Git and parser container scratch, including blame output and raw patches.",
              artifacts=(_A + "/steps/*/tasks/*/scratch/**",
                         _A + "/steps/*/tasks/*/sources/*/scratch/**",), reason=RAW),
)
