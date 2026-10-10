"""Dataset publication declarations for job_cpp_compiled_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_cpp_compiled_analysis/attempts/*"
CONSUMES = ('job_language_build',)
DATASETS = (
    indexed("cpp_build_graph", "compiled", "build", "appsec-review/retrieval-index/2",
            "C/C++ projects, compile units, sources and compile/link relations.",
            indexes=("build",), prefixes=("cpp-",), suffixes=("-compiled",),
            route="find/trace index=build relations=GENERATED_FROM,COMPILES_TO,LINKS_INTO"),
    indexed("clang_ast", "ast", "compiled", "appsec-review/retrieval-index/2",
            "Selected Clang AST records with line/column locations (partial extraction).",
            indexes=("analysis",), prefixes=("cpp-",), suffixes=("-ast",),
            route="find/search index=analysis kind=ast_node"),
    indexed("llvm_ir", "ir", "compiled", "appsec-review/retrieval-index/2",
            "LLVM IR function definitions and uniquely resolved direct calls (partial extraction).",
            indexes=("analysis",), prefixes=("cpp-",), suffixes=("-ir",),
            route="find/trace index=analysis kind=ir_entity relations=CALLS"),
    indexed("infer_observations", "infer", "scanner_findings", "appsec-review/retrieval-index/2",
            "Infer observations with bounded traces.",
            indexes=("observations",), prefixes=("cpp-",), suffixes=("-infer",),
            route="find/search index=observations; query_precomputed query_set=scanner_correlation"),
    indexed("binary_symbols", "binary", "compiled", "appsec-review/retrieval-index/2",
            "Linked artifacts with defined symbols and loader metadata.",
            indexes=("compiled",), prefixes=("cpp-",), suffixes=("-binary",),
            route="find/trace index=compiled kind=symbol"),
    indexed("cpp_blocked_branches", "acceptance", "compiled", "appsec-review/retrieval-index/2",
            "Coverage-only shards for C/C++ branches blocked by a failed build or tool.",
            indexes=("analysis",), prefixes=("cpp-",), suffixes=("-compiled", "-infer", "-binary"),
            route="coverage index=analysis"),
    artifact_only("cpp_plan_and_summary", "acceptance", "compiled", "appsec-review/cpp-compiled-analysis/2",
                  "Accepted C/C++ plan, per-branch execution receipts and summary.",
                  artifacts=(_A + "/steps/*/tasks/*/*.json",),
                  reason="plan embeds full build receipts; branch facts are published in the indexed shards",
                  sensitivity="sensitive"),
    protected("cpp_case_material", "prepare", "compiled", "application/octet-stream",
              "Materialized sources and build trees, compile and link databases, AST dumps, LLVM IR, "
              "binary records, Infer results and raw streams.",
              artifacts=("data/cpp/projects/**",),
              reason="exact compile arguments, bulky AST and IR dumps and raw tool output; bounded "
                     "source-mapped facts are indexed"),
)
