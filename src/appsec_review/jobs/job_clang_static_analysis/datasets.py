"""Publication declarations for ``job_clang_static_analysis``."""

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_clang_static_analysis/attempts/*"
CONSUMES = ("job_cpp_compiled_analysis",)
DATASETS = (
    indexed(
        "clang_static_observations", "analyze", "scanner_findings",
        "appsec-review/retrieval-index/2",
        "Source-mapped Clang-Tidy and Clang Static Analyzer observations and per-scope coverage.",
        indexes=("observations",), prefixes=("clang-static-",),
        route="find/search index=observations; query_precomputed query_set=scanner_correlation",
    ),
    indexed(
        "clang_static_scope_coverage", "acceptance", "scanner_findings",
        "appsec-review/cpp-index-coverage/1",
        "Unavailable C/C++ Clang static-analysis scopes.",
        indexes=("observations",), prefixes=("clang-static-coverage-",),
        route="coverage index=observations",
    ),
    artifact_only(
        "clang_static_summary", "acceptance", "scanner_findings",
        "appsec-review/clang-static-analysis-handoff/1",
        "Accepted Clang static-analysis summary.",
        artifacts=(_A + "/steps/acceptance/tasks/publish_handoff/*.json",),
        reason="normalized observations and coverage are published in retrieval shards",
    ),
    protected(
        "clang_static_raw", "analyze", "scanner_findings", "application/json",
        "Compile databases, raw diagnostics and container execution receipts.",
        artifacts=("data/clang-static/**",),
        reason="raw analyzer output and exact compilation context remain protected run artifacts",
    ),
)
