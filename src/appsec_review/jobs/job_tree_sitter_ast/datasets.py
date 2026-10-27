"""Dataset publication declarations for job_tree_sitter_ast.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_tree_sitter_ast/attempts/*"
CONSUMES = ('job_review_intake', 'job_target_catalog', 'job_language_build')
DATASETS = (
    indexed("tree_sitter_ast", "parse", "syntax", "appsec-review/tree-sitter-normalizer/1",
            "Bounded Tree-sitter AST nodes with byte-exact spans and parent relations, one shard per scope.",
            indexes=("analysis",), route="find/trace/search index=analysis kind=ast_node"),
    indexed("tree_sitter_coverage", "acceptance", "syntax", "appsec-review/tree-sitter-ast/1",
            "Per-scope parse dispositions, including unavailable grammars and truncation.",
            indexes=("analysis",), prefixes=("tree-sitter-coverage-",), route="coverage index=analysis"),
    artifact_only("tree_sitter_node_shards", "parse", "syntax", "appsec-review/tree-sitter-ast/1",
                  "JSONL node records and per-scope results backing the AST shards.",
                  artifacts=("data/treesitter/shards/*.jsonl", "data/treesitter/shards/*.json",
                             _A + "/steps/parse/tasks/dynamic_scopes/dynamic/*.json",
                             _A + "/steps/acceptance/tasks/publish_handoff/accepted-tree-sitter-ast.json"),
                  reason="same nodes as the accepted analysis shards; kept for deterministic reuse"),
    artifact_only("generated_source_backing", "load", "syntax", "appsec-review/generated-source-backing/1",
                  "Bounded accepted generated-source provenance; bytes reside in run-owned shared objects.",
                  artifacts=("data/treesitter/sources/*.json",),
                  reason="immutable source custody for AST and downstream resolving spans"),
    protected("tree_sitter_tool_io", "parse", "syntax", "appsec-review/container-execution/1",
              "Parser container requests, raw output and streams.",
              artifacts=("data/treesitter/work/**", "data/treesitter/inputs/**"), reason=RAW),
)
