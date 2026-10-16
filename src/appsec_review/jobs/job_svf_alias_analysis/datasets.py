"""Publication declarations for ``job_svf_alias_analysis``."""

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_svf_alias_analysis/attempts/*"
CONSUMES = ("job_cpp_compiled_analysis",)
DATASETS = (
    indexed(
        "svf_alias_sets", "analyze", "compiled",
        "appsec-review/retrieval-index/2",
        "Source-located SVF points-to sets and indirect-call target sets per linked module, with "
        "per-module closed-world coverage; a cross-check input of the graph index, not a graph producer.",
        indexes=("analysis",), prefixes=("svf-cpp-scope-",),
        route="find index=analysis kind=points_to_set|indirect_call_targets; graph cross-check input",
    ),
    indexed(
        "svf_alias_scope_coverage", "acceptance", "compiled",
        "appsec-review/cpp-index-coverage/1",
        "Unavailable C/C++ SVF points-to scopes.",
        indexes=("analysis",), prefixes=("svf-coverage-",),
        route="coverage index=analysis",
    ),
    artifact_only(
        "svf_alias_summary", "acceptance", "compiled",
        "appsec-review/svf-alias-analysis-handoff/1",
        "Accepted SVF points-to summary.",
        artifacts=(_A + "/steps/acceptance/tasks/publish_handoff/*.json",),
        reason="normalized points-to records and coverage are published in retrieval shards",
    ),
    protected(
        "svf_alias_raw", "analyze", "compiled", "application/json",
        "Module plans, compile databases, bitcode, raw SVF driver output and container execution receipts.",
        artifacts=("data/svf/**",),
        reason="raw analyzer output and exact compilation context remain protected run artifacts",
    ),
)
