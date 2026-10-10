"""Dataset publication declarations for job_cpp_symbol_index.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_cpp_symbol_index/attempts/*"
CONSUMES = ('job_cpp_compiled_analysis',)
DATASETS = (
    indexed("clangd_symbols", "index", "symbols", "appsec-review/retrieval-index/2",
            "Accepted clangd symbols with CALLS and REFERENCES relations.",
            indexes=("analysis",), prefixes=("clangd-",),
            route="find/trace index=analysis kind=symbol; query_precomputed query_set=symbol_links"),
    indexed("clangd_coverage", "acceptance", "symbols", "appsec-review/cpp-index-coverage/1",
            "Unavailable C/C++ symbol scopes.",
            indexes=("analysis",), prefixes=("clangd-coverage-",), route="coverage index=analysis"),
    artifact_only("clangd_summary", "acceptance", "symbols", "appsec-review/cpp-symbol-index/1",
                  "Symbol-index summary with per-scope counts.",
                  artifacts=(_A + "/steps/acceptance/tasks/publish_handoff/*.json",),
                  reason="counts and scope identities already published as coverage"),
    protected("clangd_tool_io", "index", "symbols", "appsec-review/container-execution/1",
              "Raw clangd index output, compile database with exact arguments and checkpoints.",
              artifacts=("data/code-index/clangd/**",),
              reason="exact compile arguments and the unbounded raw clangd index"),
)
