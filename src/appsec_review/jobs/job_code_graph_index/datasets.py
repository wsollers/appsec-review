"""Dataset publication declarations for job_code_graph_index.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced. A scope without a
usable CodeQL export still publishes its ``graph`` shards, holding only ``unavailable`` coverage rows,
so the audit reports those shards with disposition ``unavailable`` instead of a missing output. Every
scope also publishes one database-card shard (``graph-<scope_id>-database``) and one producer-neighborhood
shard (``graph-<scope_id>-producers``: flow graphs, analyzer diagnostics and clangd symbols).
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_code_graph_index/attempts/*/steps"
_SCOPES = "data/code-graph/scopes/*"
DATASETS = (
    indexed("code_graph_facts", "correlate", "graph", "appsec-review/graph-fact/1",
            "Normalized, cross-checked and SARIF-correlated code-graph facts, one shard per CodeQL scope and "
            "fact family, with a coverage row per (scope, family); unavailable scopes publish coverage only. "
            "Each scope adds one codeql_database card shard (seed ledger, mode, depth, per-family coverage, "
            "producers) and one producer_neighborhood shard (IR flow graphs, Clang analyzer diagnostics, "
            "linked clangd symbols).",
            indexes=("graph",), prefixes=("graph-",),
            route="query_code_graph (callers, callees, sinks, entry_points, paths, guards, ranges, summary, "
                  "sarif_path); list_codeql_databases; query_codeql_neighborhood "
                  "(include flow, diagnostics, symbols); query_observations (seed, function, fix_it, min_trace_length)"),
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

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_clang_static_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_clang_static_analysis", "clang_static_observations",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_clang_static_analysis", "clang_static_scope_coverage",
                         "appsec-review/cpp-index-coverage/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_clang_static_analysis", "clang_static_summary",
                         "appsec-review/clang-static-analysis-handoff/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_clang_static_analysis", "clang_static_raw",
                         "application/json", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_codeql_analysis", "codeql_predecessor_import",
                         "appsec-review/codeql-predecessor-import/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_graph_export",
                         "appsec-review/codeql-graph-export/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_observations",
                         "appsec-review/codeql-sarif-normalizer/3", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_plan_and_summary",
                         "appsec-review/codeql-analysis-handoff/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_scope_material",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpg_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpg_analysis", "cpg_graph_coverage",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpg_analysis", "cpg_scope_coverage",
                         "appsec-review/cpp-index-coverage/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpg_analysis", "cpg_summary",
                         "appsec-review/cpg-analysis/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpg_analysis", "cpg_binary",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_build_graph",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "clang_ast",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "llvm_ir",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "infer_observations",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "binary_symbols",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_blocked_branches",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_plan_and_summary",
                         "appsec-review/cpp-compiled-analysis/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_case_material",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_symbol_index", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_symbol_index", "clangd_symbols",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_symbol_index", "clangd_coverage",
                         "appsec-review/cpp-index-coverage/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_symbol_index", "clangd_summary",
                         "appsec-review/cpp-symbol-index/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_symbol_index", "clangd_tool_io",
                         "appsec-review/container-execution/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_prioritization", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_review_prioritization", "priority_items",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_review_prioritization", "prioritization_documents",
                         "appsec-review/review-prioritization/1", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_svf_alias_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_svf_alias_analysis", "svf_alias_sets",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_svf_alias_analysis", "svf_alias_scope_coverage",
                         "appsec-review/cpp-index-coverage/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_svf_alias_analysis", "svf_alias_summary",
                         "appsec-review/svf-alias-analysis-handoff/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_svf_alias_analysis", "svf_alias_raw",
                         "application/json", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "target_artifact_inputs",
                         "appsec-review/target-artifact-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "source_files",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "declaration_symbols",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "components",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "target_documents",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "build_units",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "catalog_documents",
                         "appsec-review/target-catalog/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "tree_sitter_ast",
                         "appsec-review/tree-sitter-normalizer/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "tree_sitter_coverage",
                         "appsec-review/tree-sitter-ast/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "tree_sitter_node_shards",
                         "appsec-review/tree-sitter-ast/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "generated_source_backing",
                         "appsec-review/generated-source-backing/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "tree_sitter_tool_io",
                         "appsec-review/container-execution/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    ),
    schedule_after=('job_codeql_analysis', 'job_cpp_compiled_analysis', 'job_clang_static_analysis', 'job_cpp_symbol_index', 'job_svf_alias_analysis', 'job_tree_sitter_ast', 'job_review_prioritization'),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
