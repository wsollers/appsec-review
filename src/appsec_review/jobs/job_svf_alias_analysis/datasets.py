"""Publication declarations for ``job_svf_alias_analysis``."""

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_svf_alias_analysis/attempts/*"
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

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_cpp_compiled_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
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
        InputRequirement("job_evidence_collection", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_observations",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_evidence",
                         "appsec-review/static-tool-evidence/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_io",
                         "appsec-review/container-execution/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
    ),
    schedule_after=('job_cpp_compiled_analysis',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
