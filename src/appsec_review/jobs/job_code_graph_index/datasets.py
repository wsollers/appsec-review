"""Dataset publication declarations for job_code_graph_index.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced. A scope without a
usable CodeQL export still publishes its ``graph`` shards, holding only ``unavailable`` coverage rows,
so the audit reports those shards with disposition ``unavailable`` instead of a missing output.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_code_graph_index/attempts/*/steps"
_SCOPES = "data/code-graph/scopes/*"
CONSUMES = (
    "job_codeql_analysis", "job_cpp_symbol_index", "job_cpp_compiled_analysis", "job_review_prioritization",
)
DATASETS = (
    indexed("code_graph_facts", "correlate", "graph", "appsec-review/graph-fact/1",
            "Normalized, cross-checked and SARIF-correlated code-graph facts, one shard per CodeQL scope and "
            "fact family, with a coverage row per (scope, family); unavailable scopes publish coverage only.",
            indexes=("graph",), prefixes=("graph-",),
            route="query_code_graph (callers, callees, sinks, entry_points, paths, guards, ranges, summary, "
                  "sarif_path)"),
    artifact_only("code_graph_stages", "normalize", "graph", "appsec-review/code-graph-stage/1",
                  "Per-scope normalized and cross-checked intermediate fact sets handed between units.",
                  artifacts=(_SCOPES + "/work/**",),
                  reason="intermediate copies of facts that the accepted graph shards publish"),
    artifact_only("code_graph_checkpoints", "correlate", "graph", "appsec-review/code-graph-checkpoint/1",
                  "Per-scope reuse checkpoints binding every input identity to the published shards.",
                  artifacts=(_SCOPES + "/checkpoint.json",),
                  reason="reuse bookkeeping; the shards themselves are indexed"),
    artifact_only("code_graph_summary", "acceptance", "graph", "appsec-review/code-graph-index/1",
                  "Accepted inputs, per-scope counts, coverage and gaps of one attempt.",
                  artifacts=(_A + "/load/tasks/accepted_inputs/code-graph-inputs.json",
                             _A + "/acceptance/tasks/publish_handoff/code-graph-summary.json"),
                  reason="counts and coverage are already published as graph coverage rows"),
)
